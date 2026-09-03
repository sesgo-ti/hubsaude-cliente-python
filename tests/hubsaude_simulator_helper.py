"""Helper de disponibilidade e ciclo de vida do simulador
``hubsaude-simulador`` (servidor de autorização SMART Backend Services
simulado, empacotado como JAR executável) para a suíte de
testes de integração (``tests/test_smart_token_client_integration.py``).

Sobe o JAR via processo filho (``subprocess.Popen``), numa porta TCP
livre, e aguarda o health-check em
``/.well-known/smart-configuration`` responder ``200`` antes de liberar
os testes.

Localização do JAR (variável de ambiente tem precedência sobre o
fallback, ver :func:`simulator_jar_path`):

1. variável de ambiente ``HUBSAUDE_SIMULADOR_JAR``, apontando para o
   caminho do JAR executável;
2. ``.simulator/hubsaude-simulador.jar``, relativo à raiz do
   repositório — caminho de conveniência para quem não quer reexportar
   a variável a cada sessão de shell (não versionado, ver
   ``.gitignore``).

Este repositório não tem um gerenciador de dependência para artefatos
externos como este JAR; a variável de ambiente (ou o caminho de
conveniência) é a forma mais simples e explícita de apontar para o
mesmo artefato nos ambientes (dev local e CI) onde a suíte roda.

Segue o mesmo padrão já usado por ``tests/pkcs11_softhsm_helper.py``
para outra dependência externa opcional (SoftHSM2): uma função
``*_available()`` que verifica se o pré-requisito existe no ambiente, e
``pytestmark = pytest.mark.skipif(not simulator_available(), ...)`` no
módulo de teste, em vez de falhar a suíte inteira quando o ambiente não
tem o pré-requisito.
"""

from __future__ import annotations

import os
import shutil
import socket
import ssl
import subprocess
import threading
import time
from pathlib import Path
from typing import Final

import httpx
from cryptography import x509

#: Nome da variável de ambiente que aponta para o JAR executável do
#: hubsaude-simulador. Ver docstring do módulo.
ENV_VAR_SIMULATOR_JAR: Final[str] = "HUBSAUDE_SIMULADOR_JAR"

#: Caminho de conveniência checado quando ``ENV_VAR_SIMULATOR_JAR`` não
#: está definida: ``.simulator/hubsaude-simulador.jar`` relativo à raiz
#: do repositório (``tests/`` é filho direto da raiz). Não versionado —
#: ver ``.gitignore``. Modelo mutável em nível de módulo (em vez de
#: calculado dentro da função) para permitir override direto em teste
#: via ``monkeypatch.setattr``, sem depender de filesystem real.
_LOCAL_JAR_FALLBACK: Final[Path] = Path(__file__).resolve().parent.parent / ".simulator" / "hubsaude-simulador.jar"

#: Caminho do documento de descoberta SMART, usado como health-check.
_HEALTH_PATH: Final[str] = "/.well-known/smart-configuration"

#: Tentativas/atraso padrão do polling de health-check.
_DEFAULT_MAX_ATTEMPTS: Final[int] = 60
_DEFAULT_DELAY_SECONDS: Final[float] = 1.0


def simulator_jar_path() -> Path | None:
    """Retorna o caminho do JAR do simulador, resolvendo nesta ordem:

    1. ``HUBSAUDE_SIMULADOR_JAR`` (variável de ambiente), se definida —
       tem precedência sobre o fallback para permitir override
       explícito em CI/dev sem precisar mexer no filesystem do repo.
       Se a variável estiver definida mas apontar para um arquivo
       inexistente, retorna ``None`` **sem** cair para o fallback: uma
       env var mal configurada (ex.: typo no caminho) deve ficar visível
       como erro, não ser mascarada silenciosamente por outra fonte.
    2. :data:`_LOCAL_JAR_FALLBACK` (``.simulator/hubsaude-simulador.jar``
       na raiz do repositório), se a variável não estiver definida.

    ``None`` se nenhuma das duas fontes resolver um arquivo existente.
    """
    raw = os.environ.get(ENV_VAR_SIMULATOR_JAR)
    if raw:
        env_path = Path(raw)
        return env_path if env_path.is_file() else None
    return _LOCAL_JAR_FALLBACK if _LOCAL_JAR_FALLBACK.is_file() else None


def java_available() -> bool:
    """Verifica se o executável ``java`` está disponível no ``PATH``."""
    return shutil.which("java") is not None


def simulator_available() -> bool:
    """Verifica se é possível subir o simulador neste ambiente: ``java``
    no ``PATH`` e o JAR localizável via ``HUBSAUDE_SIMULADOR_JAR``."""
    return java_available() and simulator_jar_path() is not None


def allocate_free_port() -> int:
    """Aloca uma porta TCP livre no host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


class SimulatorProcess:
    """Processo do simulador em execução, com a URL base já resolvida.

    Não deve ser instanciado diretamente pelo consumidor externo — ver
    :func:`start_simulator`, que já aguarda o simulador ficar pronto
    antes de devolver a instância.
    """

    __slots__ = ("port", "base_url", "_process")

    def __init__(self, *, port: int, base_url: str, process: "subprocess.Popen[str]") -> None:
        self.port = port
        self.base_url = base_url
        self._process = process

    def is_alive(self) -> bool:
        """``True`` se o processo do simulador ainda estiver rodando."""
        return self._process.poll() is None

    def stop(self, timeout: float = 10.0) -> None:
        """Encerra o processo do simulador: pede término
        gracioso, aguarda até ``timeout`` segundos, força o kill se
        necessário. Idempotente — chamadas extras são no-op.
        """
        if not self.is_alive():
            return
        self._process.terminate()
        try:
            self._process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=timeout)


def start_simulator(port: int | None = None) -> SimulatorProcess:
    """Sobe o simulador via ``subprocess.Popen`` do JAR localizado por
    :func:`simulator_jar_path`, numa porta livre (ou na porta informada),
    e aguarda o health-check responder antes de retornar.

    Args:
        port: porta TCP a usar; quando ``None``, aloca uma porta livre
            via :func:`allocate_free_port`.

    Returns:
        O processo em execução, já pronto para receber requisições.

    Raises:
        RuntimeError: se o JAR/``java`` não estiverem disponíveis, ou se
            o simulador não ficar pronto dentro do tempo esperado (o
            próprio processo é encerrado nesse caso, para não vazar um
            processo filho órfão).
    """
    jar_path = simulator_jar_path()
    if jar_path is None:
        raise RuntimeError(
            f"JAR do simulador nao encontrado: defina a variavel de ambiente "
            f"{ENV_VAR_SIMULATOR_JAR} apontando para o hubsaude-simulador.jar executavel, "
            f"ou copie o JAR para '{_LOCAL_JAR_FALLBACK}' (caminho de conveniencia, nao versionado)."
        )
    if not java_available():
        raise RuntimeError("Executavel 'java' nao encontrado no PATH; necessario para subir o simulador.")

    resolved_port = port if port is not None else allocate_free_port()
    base_url = f"https://localhost:{resolved_port}"

    process = subprocess.Popen(  # noqa: S603 (java local, caminho controlado pela env var acima)
        [
            "java",
            "-Djava.security.egd=file:/dev/./urandom",
            "-jar",
            str(jar_path),
            f"--server.port={resolved_port}",
            f"--server.base-url={base_url}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    _drain_output_in_background(process)

    simulator = SimulatorProcess(port=resolved_port, base_url=base_url, process=process)
    try:
        _wait_until_ready(simulator)
    except Exception:
        # Nao deixa um processo filho orfao para tras se o health-check
        # nunca ficar verde.
        simulator.stop()
        raise
    return simulator


def _drain_output_in_background(process: "subprocess.Popen[str]") -> None:
    """Consome o stdout/stderr combinados do processo numa thread daemon,
    para o buffer do subprocess nunca encher e travar o simulador."""

    def _drain() -> None:
        assert process.stdout is not None
        for _line in process.stdout:
            pass  # descarta -- so' precisamos manter o pipe drenado

    thread = threading.Thread(target=_drain, name="simulador-output-reader", daemon=True)
    thread.start()


def _wait_until_ready(
    simulator: SimulatorProcess,
    max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
    delay_seconds: float = _DEFAULT_DELAY_SECONDS,
) -> None:
    """Aguarda o health-check (``/.well-known/smart-configuration``)
    responder ``200``, verificando a cada tentativa se o processo ainda
    está vivo."""
    health_url = simulator.base_url + _HEALTH_PATH
    # verify=False: trust-all temporario, so' para o polling do
    # health-check -- o certificado real do simulador ainda nao foi
    # extraido neste ponto (isso e feito por extract_server_certificate,
    # depois que o simulador ja esta de pe).
    with httpx.Client(verify=False, timeout=5.0) as client:  # noqa: S501 (trust-all deliberado, so' health-check local)
        for attempt in range(1, max_attempts + 1):
            if not simulator.is_alive():
                raise RuntimeError(
                    "Processo do simulador terminou inesperadamente antes de ficar pronto "
                    f"(tentativa {attempt}/{max_attempts})."
                )
            try:
                response = client.get(health_url)
                if response.status_code == 200:
                    return
            except httpx.HTTPError:
                pass  # ainda nao esta pronto para aceitar conexoes -- tenta de novo
            time.sleep(delay_seconds)

    raise RuntimeError(f"Simulador nao ficou pronto em {max_attempts * delay_seconds:.0f}s. URL: {health_url}")


def extract_server_certificate(host: str, port: int, timeout: float = 5.0) -> x509.Certificate:
    """Extrai o certificado X.509 do servidor via handshake TLS com
    verificação desabilitada temporariamente (trust-all), para depois
    confiar nele "de verdade" via
    ``hubsaude_client.ssl_context_factory.build_ssl_context(trusted_cert=...)``.

    Args:
        host: hostname do servidor (ex.: ``"localhost"``).
        port: porta HTTPS do servidor.
        timeout: timeout de conexão/handshake, em segundos.

    Returns:
        O certificado X.509 apresentado pelo servidor.

    Raises:
        RuntimeError: se o servidor não apresentar nenhum certificado no
            handshake (não deveria acontecer para um servidor TLS válido).
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # nosec B501 -- trust-all deliberado, so' para extrair o certificado

    with socket.create_connection((host, port), timeout=timeout) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
            der_bytes = tls_sock.getpeercert(binary_form=True)

    if not der_bytes:
        raise RuntimeError(f"Servidor {host}:{port} nao apresentou certificado no handshake TLS.")
    return x509.load_der_x509_certificate(der_bytes)
