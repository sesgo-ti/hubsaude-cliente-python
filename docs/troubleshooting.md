# Guia para Verificação e Resolução de Problemas de Confiança em Certificados SSL/TLS

Este guia é direcionado ao desenvolvedor que está integrando um sistema
com o HubSaúde, em https://hub.saude.go.gov.br.

> **Nota:** o host `hub.saude.go.gov.br` é **ilustrativo**; use o
> endpoint informado no seu credenciamento.

O foco é ajudar a detectar se há problemas de confiança no certificado
SSL/TLS do servidor (por exemplo, se o root CA não for reconhecido
pelo seu ambiente).

O certificado do servidor pode mudar ao longo do tempo (atualmente,
é emitido pelo Let's Encrypt com root ISRG Root X1).
Vamos cobrir detecção em Python, Java, C# (.NET), JavaScript (Node.js)
e OpenSSL, além de passos para resolver importando o certificado da
CA raiz se necessário.

**Importante:** Em ambientes modernos (Python 3.10+, Java 11+, .NET 6+,
Node.js recente), o certificado deve ser confiável automaticamente.
Teste primeiro!

## Detecção de problemas

Aqui, mostramos como tentar uma conexão HTTPS simples ao endpoint
https://hub.saude.go.gov.br e capturar erros relacionados a
certificados (ex.: "PKIX path building failed" ou "SSL handshake
failed"). Se a conexão falhar com erro de confiança, prossiga para a
seção de resolução.

### Usando OpenSSL (Linha de Comando - Qualquer Plataforma)
OpenSSL é uma ferramenta gratuita e essencial para troubleshooting. Instale via pacote do seu SO (ex.: `apt install openssl` no Linux, ou via Homebrew no macOS).

Comando para testar a conexão e verificar a cadeia:
```
openssl s_client -connect hub.saude.go.gov.br:443 -servername hub.saude.go.gov.br < /dev/null
```

- **O que observar:**
    - Durante a verificação, você verá linhas como `verify return:1` para cada certificado na cadeia — isso é **normal e indica sucesso** (1 = callback retornou OK).
    - No **final da saída**, procure por `Verify return code:`:
        - `Verify return code: 0 (ok)` → cadeia válida, certificado confiável ✓
        - `Verify return code: 20 (unable to get local issuer certificate)` → CA raiz não reconhecida
        - `Verify return code: 21 (unable to verify the first certificate)` → certificado intermediário ausente
    - Procure também por `Verification: OK` para confirmação adicional.
    - Na seção "Certificate chain", verifique o issuer e root (ex.: ISRG Root X1 para Let's Encrypt).

Para um check rápido da validade:
```
echo | openssl s_client -connect hub.saude.go.gov.br:443 -servername hub.saude.go.gov.br 2>/dev/null | openssl x509 -noout -dates
```

### Em Python
Use um snippet simples com a stdlib (`ssl` + `socket`), sem depender de
nenhum pacote de terceiros. Rode com `python test_tls.py`.

```python
import socket
import ssl

endpoint = "hub.saude.go.gov.br"
port = 443

context = ssl.create_default_context()
try:
    with socket.create_connection((endpoint, port), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=endpoint) as ssock:
            print("Conexão bem-sucedida!", ssock.version(), ssock.getpeercert())
except ssl.SSLCertVerificationError as e:
    # Ex.: "unable to get local issuer certificate" -> CA não confiável.
    print("Erro de verificação de certificado:", e)
except OSError as e:
    print("Erro de conexão:", e)
```

- **Erro comum:** `ssl.SSLCertVerificationError: ... unable to get
  local issuer certificate` → CA raiz não confiável no trust store
  usado pelo `ssl.create_default_context()`.
- **Armadilha comum em Python:** bibliotecas HTTP populares (`requests`,
  `httpx` — usada por esta lib —, `urllib3`) frequentemente usam o
  pacote `certifi` como fonte de CAs em vez do trust store do sistema
  operacional. Isso significa que confiar numa CA no SO (ex.: via
  `update-ca-certificates`) pode não resolver o erro se a aplicação
  usa `certifi`; veja a seção de resolução abaixo.

### Em Java
Use um snippet simples para testar. Compile e rode com `javac Test.java && java Test`. Ajuste para sua versão de JDK.

```java
import java.net.URI;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

public class HttpsTest {
    public static void main(String[] args) {
        String endpoint = "https://hub.saude.go.gov.br";
        try {
            URL url = URI.create(endpoint).toURL();
            HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.connect();
            int responseCode = conn.getResponseCode();
            System.out.println("Conexão bem-sucedida! Código: " + responseCode);
        } catch (Exception e) {
            System.err.println("Erro: " + e.getMessage());
            // Se for javax.net.ssl.SSLHandshakeException com "PKIX path building failed",
            // é problema de confiança na CA.
            e.printStackTrace();
        }
    }
}
```

- **Erro comum:** `javax.net.ssl.SSLHandshakeException: sun.security.validator.ValidatorException: PKIX path building failed` → CA não confiável.

### Em C# (.NET)
Use um projeto console simples. Rode com `dotnet run` (para .NET Core/6+).

```csharp
using System;
using System.Net.Http;
using System.Threading.Tasks;

class Program {
    static async Task Main(string[] args) {
        string endpoint = "https://hub.saude.go.gov.br";
        using var client = new HttpClient();
        try {
            HttpResponseMessage response = await client.GetAsync(endpoint);
            response.EnsureSuccessStatusCode();
            Console.WriteLine("Conexão bem-sucedida! Código: " + response.StatusCode);
        } catch (HttpRequestException e) {
            Console.WriteLine("Erro: " + e.Message);
            // Se for "The SSL connection could not be established" com inner "Authentication failed",
            // é problema de confiança na CA.
            if (e.InnerException != null) {
                Console.WriteLine("Detalhes: " + e.InnerException.Message);
            }
        } catch (Exception ex) {
            Console.WriteLine("Exceção geral: " + ex.Message);
        }
    }
}
```

- **Erro comum:** `System.Net.Http.HttpRequestException: The SSL connection could not be established` → Verifique o inner exception para detalhes de CA.

### Em JavaScript (Node.js)
Rode com `node test.js`. Use Node.js 14+ para melhor suporte a TLS.

```javascript
const https = require('https');

const endpoint = 'https://hub.saude.go.gov.br';

https.get(endpoint, (res) => {
    console.log('Conexão bem-sucedida! Código:', res.statusCode);
}).on('error', (e) => {
    console.error('Erro:', e.message);
    // Se for "Error: unable to verify the first certificate",
    // é problema de confiança na CA.
});
```

- **Erro comum:** `Error: unable to verify the first certificate` ou `DEPTH_ZERO_SELF_SIGNED_CERT` → CA não confiável.

## Resolução de problemas

### Solução mais direta: `server_trust_anchor` (recomendada para simulador local/homologação)

Antes de qualquer alteração no sistema operacional/runtime, considere se
o problema pode ser resolvido **sem tocar em nada fora do processo**: o
builder desta biblioteca (`SmartTokenClientBuilder`) tem um método feito
especificamente para isso, `server_trust_anchor()`. Ele configura uma CA
customizada apenas para a instância do `SmartTokenClient` sendo
construída, sem alterar o trust store do sistema, do `certifi`, nem de
qualquer outra aplicação no mesmo processo/host:

```python
from hubsaude_client import SmartTokenClientBuilder

client = (
    SmartTokenClientBuilder()
    # ... demais configurações obrigatórias (client_id, signing_strategy, etc.) ...
    .server_trust_anchor("/caminho/para/root-ou-ca-do-simulador.pem")
    .build()
)
```

Aceita tanto o caminho de um arquivo PEM quanto um `cryptography.x509.Certificate`
já carregado em memória. É a via recomendada para:

- testar contra um simulador HubSaúde local (certificado autoassinado
  ou emitido por uma CA de desenvolvimento);
- homologação contra um ambiente com CA interna, ainda não presente no
  trust store público;
- qualquer cenário em que alterar o SO/runtime (`update-ca-certificates`,
  `certifi`, `cacerts` do JDK, etc. — ver seções abaixo) seria
  desproporcional ao problema, ou simplesmente não é uma opção
  disponível no ambiente (ex.: CI efêmero, container somente leitura).

As alternativas de sistema operacional/runtime cobertas no restante
desta seção continuam válidas e são necessárias quando o problema afeta
**outras aplicações no mesmo host**, não apenas este cliente — mas para
uso exclusivo desta biblioteca, `server_trust_anchor()` resolve o
problema com uma única linha de configuração, sem privilégios de admin.

### Diagnóstico de HSM/PKCS#11

Sintomas comuns ao configurar `strategy_factory.from_pkcs11()` e como
diagnosticá-los:

| Sintoma | Causa provável | Onde investigar |
| --- | --- | --- |
| `SmartTokenError` ao carregar o módulo (`pkcs11_module_path`) | Caminho incorreto para a biblioteca `.so`/`.dll` do fabricante, ou biblioteca não instalada no ambiente de execução | Confirme o caminho com o fabricante do HSM/smart card; em containers, confirme que a biblioteca nativa foi copiada para a imagem |
| `SmartTokenError` "Token nao encontrado" | `token_label` não corresponde a nenhum token inicializado no dispositivo | Liste os tokens disponíveis com a ferramenta do fabricante (ex.: `pkcs11-tool --list-slots` para a maioria dos dispositivos compatíveis com OpenSC) |
| `SmartTokenError` "Falha ao abrir sessao" | PIN incorreto, ou token bloqueado após tentativas malsucedidas anteriores | Verifique o PIN com o responsável pelo dispositivo; nunca tente PINs repetidamente sem confirmar o contador de tentativas restantes |
| `SmartTokenError` "Chave nao encontrada" | `key_label` não corresponde a nenhuma chave privada no token, ou a chave existe mas não é do tipo `PRIVATE_KEY` | Liste os objetos do token com a ferramenta do fabricante e confirme o rótulo exato (sensível a maiúsculas/minúsculas) |
| Assinatura falha em produção com `ES256`/`ES384`/`ES512` contra um HSM/token específico | Firmware/driver do dispositivo sem suporte ao mecanismo PKCS#11 combinado — mitigado nesta biblioteca desde a correção que passou a usar sempre o mecanismo puro `CKM_ECDSA` com o resumo calculado no cliente | Confirme a versão desta biblioteca em uso; se o problema persistir mesmo na versão corrigida, verifique com o fabricante quais mecanismos ECDSA o dispositivo expõe |

Ferramentas de linha de comando genéricas (não específicas desta
biblioteca) úteis para inspecionar um token PKCS#11 diretamente:
`pkcs11-tool` (pacote `opensc`) e `p11tool` (pacote `gnutls-bin`/
`gnutls-utils`, conforme a distribuição).


### Importando a CA raiz no trust store do sistema/runtime

Se detectar um erro de confiança, o problema geralmente é que a
CA raiz (atualmente ISRG Root X1 do Let's Encrypt) não está no
trust store do seu ambiente. Primeiro,
**descubra o certificado atual da CA**. Depois,
importe-o manualmente.

> **Nota**
> Isso é um workaround para legados; priorize atualizar seu runtime/SO
> para versões modernas.

### Descobrindo o certificado da CA Raiz do HubSaúde
Use OpenSSL para extrair a cadeia completa e identificar o root:

```
echo | openssl s_client -connect hub.saude.go.gov.br:443 -servername hub.saude.go.gov.br -showcerts 2>/dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > chain.pem
```

- Isso salva a cadeia em `chain.pem`.
- Abra o arquivo e procure o último certificado (o root, com "Issuer" igual a "Subject").
- Atualmente, é ISRG Root X1. Baixe o PEM oficial de fontes confiáveis como https://letsencrypt.org/certs/isrgrootx1.pem (verifique sempre o site da CA emitente).

Para automatizar a extração do root:
- Use um editor de texto ou script para isolar o bloco "-BEGIN CERTIFICATE-" do root.

### Importando em Python
Depende de qual trust store a sua aplicação/biblioteca HTTP usa:

- **`ssl.create_default_context()` (stdlib pura)**: por padrão, usa o
  trust store do sistema operacional. Atualize-o (ex.:
  `update-ca-certificates` no Ubuntu/Debian, após copiar `root.pem`
  para `/usr/local/share/ca-certificates/`) e reinicie a aplicação.
- **`certifi`** (usado por padrão por `requests`, `httpx`, `urllib3` —
  `httpx` é dependência desta biblioteca): o pacote mantém seu
  *próprio* bundle de CAs, independente do SO. Para confiar num root
  adicional sem depender de atualização do `certifi`, aponte
  explicitamente para um bundle customizado que inclua o `root.pem`
  baixado, por exemplo via `SSL_CERT_FILE` (afeta a stdlib `ssl`) ou
  passando `verify=<caminho-do-bundle>` na configuração da biblioteca
  HTTP usada. Consulte a documentação da biblioteca HTTP específica
  para o parâmetro equivalente.

Verifique com o snippet da seção de detecção acima após o ajuste.

### Importando em Java (JDK/JRE)
Adicione ao trust store `cacerts` (padrão em `$JAVA_HOME/lib/security/cacerts`).

Comando (substitua `root.pem` pelo arquivo do root CA):
```
keytool -import -trustcacerts -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit -noprompt -alias isrgrootx1 -file root.pem
```

- Rode como admin se necessário.
- Verifique: `keytool -list -keystore $JAVA_HOME/lib/security/cacerts -storepass changeit | grep isrgrootx1`.
- Reinicie sua app e teste novamente.

Para apps embed (ex.: em JAR), use um trust store custom via código:
```java
System.setProperty("javax.net.ssl.trustStore", "custom-cacerts");
System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
```

### Importando em .NET (Windows)
Adicione ao store de raízes confiáveis do máquina (para apps .NET Framework/Core).

Via PowerShell (rode como admin; substitua `root.cer` pelo arquivo DER/PEM convertido):
```
Import-Certificate -FilePath "root.cer" -CertStoreLocation Cert:\LocalMachine\Root
```

- Converta PEM para CER se necessário: Use OpenSSL `openssl x509 -outform der -in root.pem -out root.cer`.
- Para .NET Core em Linux/macOS, atualize o trust store do SO (ex.: `update-ca-certificates` no Ubuntu).
- Em código, para bypass temporário (não recomendado para prod):
```csharp
using System.Net;
ServicePointManager.ServerCertificateValidationCallback = (sender, cert, chain, errors) => true; // Use com cautela!
```

### Importando em JavaScript (Node.js)
Defina a variável de ambiente `NODE_EXTRA_CA_CERTS` para apontar ao arquivo PEM do root.

Exemplo:
```
export NODE_EXTRA_CA_CERTS=/path/to/root.pem
node your-app.js
```

- Ou em código (para https agent custom):
```javascript
const https = require('https');
const fs = require('fs');

const options = {
    ca: [fs.readFileSync('/path/to/root.pem')]
};

https.get('https://hub.saude.go.gov.br', options, (res) => {
    // ...
});
```

- Para apps em produção, inclua o PEM no bundle ou use um pacote como `ssl-root-cas`.

## Considerações finais
- **Atualize:** migre para versões modernas (Python 3.12+ — a própria
  `hubsaude-cliente-python` exige Python 3.12 —, Java 21+, .NET 8+,
  Node 20+) para evitar este problema de *handshake* TLS.
- **Teste em produção:** use ferramentas como SSL Labs (https://www.ssllabs.com/ssltest/) para auditar o servidor.
- **Segurança:** baixe certificados apenas de fontes oficiais para evitar MITM.
- Se persistir problemas, contate o suporte do serviço ou verifique logs do servidor.
