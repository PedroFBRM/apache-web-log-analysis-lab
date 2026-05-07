# Apache Web Log Analysis Lab

> Blue Team lab focused on analyzing Apache HTTP server logs to detect web scanning activity, directory enumeration, and path traversal attempts.

---

## Objective

Install and expose an Apache web server in an isolated lab environment, simulate automated web scanning using industry-standard tools, and analyze the generated logs from a Blue Team perspective — identifying attack patterns, tool signatures, and indicators of malicious reconnaissance activity.

---

## Environment

| Component   | Details                                                 |
| ----------- | ------------------------------------------------------- |
| Attacker VM | Kali Linux                                              |
| Target VM   | Debian 13                                               |
| Network     | NAT Network (VirtualBox)                                |
| Attacker IP | 10.0.2.5                                                |
| Target IP   | 10.0.2.15                                               |
| Web server  | Apache 2.4.67                                           |
| Log sources | /var/log/apache2/access.log, /var/log/apache2/error.log |
| HTTP port   | 80                                                      |

---

## Steps Performed

### 1. Apache Service Validation

Confirmed that the Apache HTTP server was active and running on the target machine.

```bash
sudo systemctl status apache2 --no-pager
```

Result: `active (running)` since Wed 2026-05-06 21:09:17. Apache 2.4.67 (Debian), Main PID 3164, 55 tasks active.

---

### 2. Target IP Identification

Identified the IP address of the Debian target machine.

```bash
ip a
```

**Target IP:** `10.0.2.15/24` — interface `enp0s3`

---

### 3. Connectivity Test

Verified network connectivity between the Kali attacker machine and the Debian target.

```bash
ping -c 4 10.0.2.15
```

**Result:** 4 packets transmitted, 4 received, 0% packet loss. RTT min/avg/max: 0.495/1.288/2.139ms.

---

### 4. Apache Browser Test

Accessed the Apache server from the Kali browser to confirm HTTP service availability.

```
http://10.0.2.15
```

**Result:** Apache2 Debian Default Page loaded successfully — confirming the web server was reachable and responding to HTTP requests.

---

### 5. Web Content Setup

Created test directories and pages on the target server to simulate a realistic web application structure.

```bash
sudo mkdir -p /var/www/html/admin
sudo mkdir -p /var/www/html/backup
sudo mkdir -p /var/www/html/login
echo "<h1>Admin Panel</h1>" | sudo tee /var/www/html/admin/index.html
echo "<h1>Login Page</h1>" | sudo tee /var/www/html/login/index.html
```

Directories created: `/admin`, `/backup`, `/login`

---

### 6. Nikto Scan

Ran Nikto against the target web server to simulate automated vulnerability scanning.

```bash
nikto -h http://10.0.2.15
```

**Nikto v2.5.0 — Start Time: 2026-05-06 20:16:56 — End Time: 20:17:13 (17 seconds)**

Findings reported by Nikto:

- **Server:** Apache/2.4.67 (Debian)
- **Missing header:** `X-Frame-Options` — clickjacking protection absent
- **Missing header:** `X-Content-Type-Options` — MIME sniffing protection absent
- **ETag leak:** Server may leak inode numbers via ETags (CVE-2003-1418)
- **Allowed methods:** GET, POST, OPTIONS, HEAD
- **Interesting directories found:** `/admin/`, `/backup/`, `/login/`
- **Confirmed:** `/admin/index.html` — Admin login page accessible
- **Total requests:** 8102 in 17 seconds

---

### 7. Dirb Scan

Ran Dirb to perform directory brute forcing against the target web server.

```bash
dirb http://10.0.2.15
```

**DIRB v2.22 — Start: Wed May 6 20:19:50 2026 — End: 20:19:59 2026 (9 seconds)**

Wordlist used: `/usr/share/dirb/wordlists/common.txt` — 4612 words tested

Directories and files found:

| URL                               | Code | Size  |
| --------------------------------- | ---- | ----- |
| http://10.0.2.15/index.html       | 200  | 10703 |
| http://10.0.2.15/server-status    | 403  | 314   |
| http://10.0.2.15/admin/           | 200  | —     |
| http://10.0.2.15/admin/index.html | 200  | 21    |
| http://10.0.2.15/backup/          | 200  | —     |
| http://10.0.2.15/login/           | 200  | —     |
| http://10.0.2.15/login/index.html | 200  | 20    |

**Warning:** `/backup/` directory listing is enabled — no index file present, directory contents directly browsable.

**Total downloaded:** 13836 bytes — **Found:** 4 resources

---

### 8. Access Log Analysis

Inspected raw access log entries to identify the attack pattern.

```bash
sudo cat /var/log/apache2/access.log
```

Sample entries from the Nikto scan phase (21:18:32):

```
10.0.2.5 - - [06/May/2026:21:18:32 -0300] "GET /10.0.2.15.tar.bz2 HTTP/1.1" 404 527
10.0.2.5 - - [06/May/2026:21:18:32 -0300] "GET /10_0_2_15.gz HTTP/1.1" 404 527
10.0.2.5 - - [06/May/2026:21:18:32 -0300] "GET /10.0.2.15.sql HTTP/1.1" 404 527
10.0.2.5 - - [06/May/2026:21:18:32 -0300] "GET /10.0.2.15.zip HTTP/1.1" 404 527
```

Sample entries from the Dirb scan phase (21:21:34):

```
10.0.2.5 - - [06/May/2026:21:21:34 -0300] "GET /login/xsql HTTP/1.1" 404 472
10.0.2.5 - - [06/May/2026:21:21:34 -0300] "GET /login/xxx HTTP/1.1" 404 472
10.0.2.5 - - [06/May/2026:21:21:34 -0300] "GET /login/zimbra HTTP/1.1" 404 472
10.0.2.5 - - [06/May/2026:21:21:34 -0300] "GET /login/zoom HTTP/1.1" 404 472
```

**Pattern observed:** Hundreds of sequential requests within the same second, all targeting non-existent paths — consistent with automated scanning behavior.

---

### 9. Scan Pattern by Source IP

Filtered all access log entries originating from the attacker IP.

```bash
sudo grep "10.0.2.5" /var/log/apache2/access.log | head -30
```

Additional patterns observed:

- Nikto attempted to access backup files using the server IP as filename (e.g., `10.0.2.15.tar.bz2`, `10.0.2.15.sql`, `10.0.2.15.zip`)
- Dirb iterated through alphabetically ordered wordlists targeting each discovered directory
- Both tools generated requests at machine speed — multiple entries per second from the same source port range

---

### 10. HTTP Status Code Distribution

Counted requests by HTTP response code to quantify the attack surface.

```bash
sudo grep " 200 " /var/log/apache2/access.log | wc -l
sudo grep " 403 " /var/log/apache2/access.log | wc -l
sudo grep " 404 " /var/log/apache2/access.log | wc -l
```

| HTTP Code | Meaning                                       | Count |
| --------- | --------------------------------------------- | ----- |
| 200       | OK — resource found and served                | 177   |
| 403       | Forbidden — resource exists but access denied | 26    |
| 404       | Not Found — resource does not exist           | 21740 |

**Total 404 errors: 21,740** — the overwhelming majority of requests targeted paths that do not exist, which is the defining characteristic of automated directory brute forcing.

---

### 11. Total Requests by Attacker IP

Counted all access log entries originating from the attacker.

```bash
sudo grep "10.0.2.5" /var/log/apache2/access.log | wc -l
```

**Total requests from 10.0.2.5: 21,962**

---

### 12. Tool Signature Identification

Searched for scanner-specific signatures in the access log.

#### Nikto signature

```bash
sudo grep "nikto" /var/log/apache2/access.log | head -5
```

Result:

```
10.0.2.5 - - [06/May/2026:21:18:32 -0300] "PUT /nikto-test-pk9VPSjF.html HTTP/1.1" 405 590 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

Nikto created a test file (`nikto-test-pk9VPSjF.html`) via PUT request to verify write permissions on the server.

#### Dirb signature

```bash
sudo grep "DirBuster\|dirb" /var/log/apache2/access.log | head -5
```

Result:

```
10.0.2.5 - - [06/May/2026:21:21:26 -0300] "GET /dirb HTTP/1.1" 404 472
10.0.2.5 - - [06/May/2026:21:21:26 -0300] "GET /dirbmark HTTP/1.1" 404 472
10.0.2.5 - - [06/May/2026:21:21:29 -0300] "GET /admin/dirb HTTP/1.1" 404 472
10.0.2.5 - - [06/May/2026:21:21:29 -0300] "GET /admin/dirbmark HTTP/1.1" 404 472
10.0.2.5 - - [06/May/2026:21:21:32 -0300] "GET /login/dirb HTTP/1.1" 404 472
```

Dirb's own name appears in the wordlist it uses, leaving a clear signature in the logs.

---

### 13. Error Log Analysis

Inspected the Apache error log for server-side security events triggered by the scan.

```bash
sudo cat /var/log/apache2/error.log
```

Critical events found:

#### Path Traversal Attempts (Directory Traversal)

Nikto attempted to access sensitive system files by traversing directory boundaries:

```
[client 10.0.2.5] AH10244: invalid URI path (/../../../../../../../../../../../../etc/shadow)
[client 10.0.2.5] AH10244: invalid URI path (/../../../../../../../../../../etc/passwd)
[client 10.0.2.5] AH10244: invalid URI path (/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/windows/win.ini)
[client 10.0.2.5] AH10244: invalid URI path (/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd)
[client 10.0.2.5] AH10244: invalid URI path (/../../../../../../../../../boot.ini)
[client 10.0.2.5] AH10244: invalid URI path (/../../../../winnt/repair/sam._)
```

Targets included: `/etc/passwd`, `/etc/shadow`, `boot.ini`, `win.ini`, Windows SAM database — all classic path traversal targets.

#### Invalid HTTP Methods

Nikto tested non-standard HTTP methods to identify misconfigurations:

```
[client 10.0.2.5] AH00135: Invalid method in request DIWHWPJH / HTTP/1.1
[client 10.0.2.5] AH00135: Invalid method in request DEBUG / HTTP/1.1
[client 10.0.2.5] AH00135: Invalid method in request TRACK / HTTP/1.0
[client 10.0.2.5] AH00135: Invalid method in request SEARCH / HTTP/1.1
[client 10.0.2.5] AH00135: Invalid method in request INDEX / HTTP/1.1
```

#### Protected File Access Attempts

Both tools attempted to access Apache-protected configuration files:

```
[client 10.0.2.5] AH01630: client denied by server configuration: /var/www/html/.htpasswd
[client 10.0.2.5] AH01630: client denied by server configuration: /var/www/html/.htaccess
[client 10.0.2.5] AH01630: client denied by server configuration: /var/www/html/server-status
[client 10.0.2.5] AH01630: client denied by server configuration: /var/www/html/admin/.htpasswd
[client 10.0.2.5] AH01630: client denied by server configuration: /var/www/html/login/.htpasswd
```

#### VMware-Specific Path Traversal

Nikto also tested for VMware infrastructure exposure:

```
[client 10.0.2.5] AH10244: invalid URI path (/sdk/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/etc/vmware/hostd/vmInventory.xml)
```

---

## Analysis

The access and error logs revealed a two-phase automated attack pattern originating from a single IP address (`10.0.2.5`) targeting the Apache web server on port 80.

### Phase 1 — Vulnerability Scanning (Nikto, 21:14 to 21:18)

Nikto performed 8,102 requests in 17 seconds, testing for known web vulnerabilities, missing security headers, dangerous HTTP methods, and path traversal vectors. The error log captured multiple attempts to access `/etc/passwd`, `/etc/shadow`, `boot.ini`, and Windows SAM files — all blocked by Apache's URI validation. Nikto also attempted a PUT request to create a test file on the server, confirming it was testing for write permissions.

### Phase 2 — Directory Enumeration (Dirb, 21:19 to 21:21)

Dirb tested 4,612 words from its common wordlist against the root and each discovered subdirectory. This generated the bulk of the 21,740 `404` errors observed. Dirb successfully identified `/admin/`, `/backup/`, and `/login/` as valid directories. The `/backup/` directory was found to have directory listing enabled — a significant misconfiguration that would allow an attacker to browse its contents directly.

### Combined Assessment

The concentration of 21,962 HTTP requests from a single source IP within approximately 7 minutes, combined with the presence of path traversal attempts, invalid HTTP methods, and tool-specific signatures in both the access and error logs, constitutes clear evidence of automated web reconnaissance activity.

No successful exploitation was observed. All path traversal attempts were rejected by Apache's URI validation engine. Access to protected files (`.htpasswd`, `.htaccess`, `server-status`) was denied by server configuration.

---

## Key Indicators

| Indicator                    | Value                                          |
| ---------------------------- | ---------------------------------------------- |
| Attacker IP                  | 10.0.2.5                                       |
| Target IP                    | 10.0.2.15                                      |
| Target port                  | 80 (HTTP)                                      |
| Web server                   | Apache 2.4.67 (Debian)                         |
| Tools identified             | Nikto v2.5.0, Dirb v2.22                       |
| Total requests from attacker | 21,962                                         |
| HTTP 200 responses           | 177                                            |
| HTTP 403 responses           | 26                                             |
| HTTP 404 responses           | 21,740                                         |
| Directories discovered       | /admin/, /backup/, /login/                     |
| Path traversal attempts      | Multiple (all blocked)                         |
| Invalid HTTP methods tested  | TRACK, DEBUG, SEARCH, INDEX                    |
| Sensitive files targeted     | /etc/passwd, /etc/shadow, .htpasswd, .htaccess |
| Successful exploitation      | None                                           |
| Time window                  | 21:14 to 21:21 (2026-05-06)                    |

---

## Defensive Recommendations

Based on the findings, the following controls are recommended:

- Add security headers to Apache configuration: `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`
- Disable ETag headers to prevent inode information leakage
- Restrict allowed HTTP methods to GET, POST, HEAD only
- Disable directory listing for all directories, especially `/backup/`
- Restrict access to `/server-status` to localhost only
- Implement rate limiting to block IPs generating excessive requests per second
- Deploy a WAF (Web Application Firewall) to detect and block path traversal patterns
- Monitor `error.log` continuously for `AH10244` (invalid URI path) events
- Remove or restrict access to sensitive directories (`/admin/`, `/backup/`) from public exposure
- Hide the Apache version from HTTP response headers (`ServerTokens Prod`, `ServerSignature Off`)

---

## Conclusion

This lab demonstrated how automated web scanning tools leave distinct and identifiable patterns across both Apache access and error logs. By correlating the volume of `404` errors, the presence of path traversal attempts in `error.log`, invalid HTTP method requests, and tool-specific signatures in request paths and user-agent strings, it was possible to reconstruct the full attack timeline and identify the tools used — without any prior knowledge of the attacker's actions.

The exercise reinforces the importance of web server log monitoring, security header configuration, and directory access controls as foundational Blue Team practices for web-facing infrastructure.

---

## Tools Used

- Kali Linux
- Debian 13
- Apache 2.4.67
- Nikto v2.5.0
- Dirb v2.22
- grep, wc, cat

---

---

# Apache Web Log Analysis Lab

> Laboratório Blue Team focado em analisar logs do servidor Apache para detectar varreduras web, enumeração de diretórios e tentativas de path traversal.

---

## Objetivo

Instalar e expor um servidor web Apache em um ambiente de laboratório isolado, simular varreduras automatizadas utilizando ferramentas amplamente usadas em testes de segurança, e analisar os logs gerados sob uma perspectiva Blue Team — identificando padrões de ataque, assinaturas de ferramentas e indicadores de atividade de reconhecimento malicioso.

---

## Ambiente

| Componente     | Detalhes                                                |
| -------------- | ------------------------------------------------------- |
| VM Atacante    | Kali Linux                                              |
| VM Alvo        | Debian 13                                               |
| Rede           | NAT Network (VirtualBox)                                |
| IP do Atacante | 10.0.2.5                                                |
| IP do Alvo     | 10.0.2.15                                               |
| Servidor web   | Apache 2.4.67                                           |
| Fontes de log  | /var/log/apache2/access.log, /var/log/apache2/error.log |
| Porta HTTP     | 80                                                      |

---

## Etapas Realizadas

### 1. Validação do Serviço Apache

Confirmado que o servidor Apache estava ativo e em execução na máquina alvo.

```bash
sudo systemctl status apache2 --no-pager
```

Resultado: `active (running)` desde Wed 2026-05-06 21:09:17. Apache 2.4.67 (Debian), PID principal 3164, 55 tarefas ativas.

---

### 2. Identificação do IP do Alvo

Identificado o endereço IP da máquina Debian alvo.

```bash
ip a
```

**IP do alvo:** `10.0.2.15/24` — interface `enp0s3`

---

### 3. Teste de Conectividade

Verificada a conectividade de rede entre o Kali e o Debian.

```bash
ping -c 4 10.0.2.15
```

**Resultado:** 4 pacotes transmitidos, 4 recebidos, 0% de perda. RTT min/avg/max: 0.495/1.288/2.139ms.

---

### 4. Teste do Apache no Navegador

Acessado o servidor Apache a partir do navegador do Kali para confirmar disponibilidade do serviço HTTP.

```
http://10.0.2.15
```

**Resultado:** Página padrão do Apache2 Debian carregada com sucesso — confirmando que o servidor web estava acessível e respondendo a requisições HTTP.

---

### 5. Criação de Conteúdo de Teste

Criados diretórios e páginas de teste no servidor alvo para simular uma estrutura de aplicação web realista.

```bash
sudo mkdir -p /var/www/html/admin
sudo mkdir -p /var/www/html/backup
sudo mkdir -p /var/www/html/login
echo "<h1>Admin Panel</h1>" | sudo tee /var/www/html/admin/index.html
echo "<h1>Login Page</h1>" | sudo tee /var/www/html/login/index.html
```

Diretórios criados: `/admin`, `/backup`, `/login`

---

### 6. Scan com Nikto

Executado o Nikto contra o servidor web alvo para simular varredura automatizada de vulnerabilidades.

```bash
nikto -h http://10.0.2.15
```

**Nikto v2.5.0 — Início: 2026-05-06 20:16:56 — Fim: 20:17:13 (17 segundos)**

Achados reportados pelo Nikto:

- **Servidor:** Apache/2.4.67 (Debian)
- **Header ausente:** `X-Frame-Options` — proteção contra clickjacking ausente
- **Header ausente:** `X-Content-Type-Options` — proteção contra MIME sniffing ausente
- **Vazamento de ETag:** Servidor pode vazar números de inode via ETags (CVE-2003-1418)
- **Métodos permitidos:** GET, POST, OPTIONS, HEAD
- **Diretórios interessantes encontrados:** `/admin/`, `/backup/`, `/login/`
- **Confirmado:** `/admin/index.html` — página de admin acessível publicamente
- **Total de requisições:** 8102 em 17 segundos

---

### 7. Scan com Dirb

Executado o Dirb para realizar força bruta de diretórios contra o servidor web alvo.

```bash
dirb http://10.0.2.15
```

**DIRB v2.22 — Início: Wed May 6 20:19:50 2026 — Fim: 20:19:59 2026 (9 segundos)**

Wordlist utilizada: `/usr/share/dirb/wordlists/common.txt` — 4612 palavras testadas

Diretórios e arquivos encontrados:

| URL                               | Código | Tamanho |
| --------------------------------- | ------ | ------- |
| http://10.0.2.15/index.html       | 200    | 10703   |
| http://10.0.2.15/server-status    | 403    | 314     |
| http://10.0.2.15/admin/           | 200    | —       |
| http://10.0.2.15/admin/index.html | 200    | 21      |
| http://10.0.2.15/backup/          | 200    | —       |
| http://10.0.2.15/login/           | 200    | —       |
| http://10.0.2.15/login/index.html | 200    | 20      |

**Aviso:** O diretório `/backup/` está com listagem habilitada — sem arquivo de índice, o conteúdo do diretório pode ser navegado diretamente.

**Total baixado:** 13836 bytes — **Encontrados:** 4 recursos

---

### 8. Análise do Log de Acesso

Inspecionadas as entradas brutas do log de acesso para identificar o padrão de ataque.

```bash
sudo cat /var/log/apache2/access.log
```

Entradas da fase de scan do Nikto (21:18:32):

```
10.0.2.5 - - [06/May/2026:21:18:32 -0300] "GET /10.0.2.15.tar.bz2 HTTP/1.1" 404 527
10.0.2.5 - - [06/May/2026:21:18:32 -0300] "GET /10_0_2_15.gz HTTP/1.1" 404 527
10.0.2.5 - - [06/May/2026:21:18:32 -0300] "GET /10.0.2.15.sql HTTP/1.1" 404 527
10.0.2.5 - - [06/May/2026:21:18:32 -0300] "GET /10.0.2.15.zip HTTP/1.1" 404 527
```

Entradas da fase de scan do Dirb (21:21:34):

```
10.0.2.5 - - [06/May/2026:21:21:34 -0300] "GET /login/xsql HTTP/1.1" 404 472
10.0.2.5 - - [06/May/2026:21:21:34 -0300] "GET /login/xxx HTTP/1.1" 404 472
10.0.2.5 - - [06/May/2026:21:21:34 -0300] "GET /login/zimbra HTTP/1.1" 404 472
10.0.2.5 - - [06/May/2026:21:21:34 -0300] "GET /login/zoom HTTP/1.1" 404 472
```

**Padrão observado:** Centenas de requisições sequenciais dentro do mesmo segundo, todas direcionadas a caminhos inexistentes — comportamento consistente com varredura automatizada.

---

### 9. Padrão de Scan por IP de Origem

Filtradas todas as entradas do log de acesso originadas do IP do atacante.

```bash
sudo grep "10.0.2.5" /var/log/apache2/access.log | head -30
```

Padrões adicionais observados:

- O Nikto tentou acessar arquivos de backup usando o IP do servidor como nome de arquivo (ex: `10.0.2.15.tar.bz2`, `10.0.2.15.sql`, `10.0.2.15.zip`)
- O Dirb iterou por wordlists em ordem alfabética direcionando cada diretório descoberto
- Ambas as ferramentas geraram requisições em velocidade de máquina — múltiplas entradas por segundo na mesma faixa de porta de origem

---

### 10. Distribuição de Códigos de Status HTTP

Contabilizadas as requisições por código de resposta HTTP para quantificar a superfície de ataque.

```bash
sudo grep " 200 " /var/log/apache2/access.log | wc -l
sudo grep " 403 " /var/log/apache2/access.log | wc -l
sudo grep " 404 " /var/log/apache2/access.log | wc -l
```

| Código HTTP | Significado                                 | Quantidade |
| ----------- | ------------------------------------------- | ---------- |
| 200         | OK — recurso encontrado e entregue          | 177        |
| 403         | Proibido — recurso existe mas acesso negado | 26         |
| 404         | Não encontrado — recurso não existe         | 21.740     |

**Total de erros 404: 21.740** — a esmagadora maioria das requisições foi direcionada a caminhos inexistentes, o que é a característica definidora de força bruta automatizada de diretórios.

---

### 11. Total de Requisições por IP do Atacante

Contabilizadas todas as entradas do log de acesso originadas do atacante.

```bash
sudo grep "10.0.2.5" /var/log/apache2/access.log | wc -l
```

**Total de requisições de 10.0.2.5: 21.962**

---

### 12. Identificação de Assinatura das Ferramentas

Buscadas assinaturas específicas dos scanners no log de acesso.

#### Assinatura do Nikto

```bash
sudo grep "nikto" /var/log/apache2/access.log | head -5
```

Resultado:

```
10.0.2.5 - - [06/May/2026:21:18:32 -0300] "PUT /nikto-test-pk9VPSjF.html HTTP/1.1" 405 590 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
```

O Nikto criou um arquivo de teste (`nikto-test-pk9VPSjF.html`) via requisição PUT para verificar permissões de escrita no servidor.

#### Assinatura do Dirb

```bash
sudo grep "DirBuster\|dirb" /var/log/apache2/access.log | head -5
```

Resultado:

```
10.0.2.5 - - [06/May/2026:21:21:26 -0300] "GET /dirb HTTP/1.1" 404 472
10.0.2.5 - - [06/May/2026:21:21:26 -0300] "GET /dirbmark HTTP/1.1" 404 472
10.0.2.5 - - [06/May/2026:21:21:29 -0300] "GET /admin/dirb HTTP/1.1" 404 472
10.0.2.5 - - [06/May/2026:21:21:29 -0300] "GET /admin/dirbmark HTTP/1.1" 404 472
10.0.2.5 - - [06/May/2026:21:21:32 -0300] "GET /login/dirb HTTP/1.1" 404 472
```

O próprio nome do Dirb aparece na wordlist que ele utiliza, deixando uma assinatura clara nos logs.

---

### 13. Análise do Log de Erros

Inspecionado o log de erros do Apache para identificar eventos de segurança gerados pelo scan.

```bash
sudo cat /var/log/apache2/error.log
```

Eventos críticos encontrados:

#### Tentativas de Path Traversal (Directory Traversal)

O Nikto tentou acessar arquivos sensíveis do sistema atravessando limites de diretório:

```
[client 10.0.2.5] AH10244: invalid URI path (/../../../../../../../../../../../../etc/shadow)
[client 10.0.2.5] AH10244: invalid URI path (/../../../../../../../../../../etc/passwd)
[client 10.0.2.5] AH10244: invalid URI path (/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/windows/win.ini)
[client 10.0.2.5] AH10244: invalid URI path (/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd)
[client 10.0.2.5] AH10244: invalid URI path (/../../../../../../../../../boot.ini)
[client 10.0.2.5] AH10244: invalid URI path (/../../../../winnt/repair/sam._)
```

Alvos incluíram: `/etc/passwd`, `/etc/shadow`, `boot.ini`, `win.ini`, banco SAM do Windows — todos alvos clássicos de path traversal.

#### Métodos HTTP Inválidos

O Nikto testou métodos HTTP não padrão para identificar configurações incorretas:

```
[client 10.0.2.5] AH00135: Invalid method in request DIWHWPJH / HTTP/1.1
[client 10.0.2.5] AH00135: Invalid method in request DEBUG / HTTP/1.1
[client 10.0.2.5] AH00135: Invalid method in request TRACK / HTTP/1.0
[client 10.0.2.5] AH00135: Invalid method in request SEARCH / HTTP/1.1
[client 10.0.2.5] AH00135: Invalid method in request INDEX / HTTP/1.1
```

#### Tentativas de Acesso a Arquivos Protegidos

Ambas as ferramentas tentaram acessar arquivos de configuração protegidos pelo Apache:

```
[client 10.0.2.5] AH01630: client denied by server configuration: /var/www/html/.htpasswd
[client 10.0.2.5] AH01630: client denied by server configuration: /var/www/html/.htaccess
[client 10.0.2.5] AH01630: client denied by server configuration: /var/www/html/server-status
[client 10.0.2.5] AH01630: client denied by server configuration: /var/www/html/admin/.htpasswd
[client 10.0.2.5] AH01630: client denied by server configuration: /var/www/html/login/.htpasswd
```

#### Path Traversal Específico para VMware

O Nikto também testou exposição de infraestrutura VMware:

```
[client 10.0.2.5] AH10244: invalid URI path (/sdk/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/%2E%2E/etc/vmware/hostd/vmInventory.xml)
```

---

## Análise

Os logs de acesso e de erros revelaram um padrão de ataque automatizado em duas fases, originado de um único endereço IP (`10.0.2.5`) direcionado ao servidor Apache na porta 80.

### Fase 1 — Varredura de Vulnerabilidades (Nikto, 21:14 a 21:18)

O Nikto realizou 8.102 requisições em 17 segundos, testando vulnerabilidades web conhecidas, headers de segurança ausentes, métodos HTTP perigosos e vetores de path traversal. O log de erros registrou múltiplas tentativas de acesso a `/etc/passwd`, `/etc/shadow`, `boot.ini` e ao banco SAM do Windows — todas bloqueadas pela validação de URI do Apache. O Nikto também tentou uma requisição PUT para criar um arquivo de teste no servidor, confirmando que estava verificando permissões de escrita.

### Fase 2 — Enumeração de Diretórios (Dirb, 21:19 a 21:21)

O Dirb testou 4.612 palavras de sua wordlist comum contra o diretório raiz e cada subdiretório descoberto. Isso gerou a maior parte dos 21.740 erros `404` observados. O Dirb identificou com sucesso `/admin/`, `/backup/` e `/login/` como diretórios válidos. O diretório `/backup/` foi encontrado com listagem habilitada — uma configuração incorreta significativa que permitiria a um atacante navegar pelo seu conteúdo diretamente.

### Avaliação Combinada

A concentração de 21.962 requisições HTTP de um único IP de origem em aproximadamente 7 minutos, combinada com a presença de tentativas de path traversal, requisições com métodos HTTP inválidos e assinaturas específicas de ferramentas nos logs de acesso e de erros, constitui evidência clara de atividade automatizada de reconhecimento web.

Nenhuma exploração bem-sucedida foi observada. Todas as tentativas de path traversal foram rejeitadas pelo mecanismo de validação de URI do Apache. O acesso a arquivos protegidos (`.htpasswd`, `.htaccess`, `server-status`) foi negado pela configuração do servidor.

---

## Indicadores Principais

| Indicador                        | Valor                                          |
| -------------------------------- | ---------------------------------------------- |
| IP do atacante                   | 10.0.2.5                                       |
| IP do alvo                       | 10.0.2.15                                      |
| Porta alvo                       | 80 (HTTP)                                      |
| Servidor web                     | Apache 2.4.67 (Debian)                         |
| Ferramentas identificadas        | Nikto v2.5.0, Dirb v2.22                       |
| Total de requisições do atacante | 21.962                                         |
| Respostas HTTP 200               | 177                                            |
| Respostas HTTP 403               | 26                                             |
| Respostas HTTP 404               | 21.740                                         |
| Diretórios descobertos           | /admin/, /backup/, /login/                     |
| Tentativas de path traversal     | Múltiplas (todas bloqueadas)                   |
| Métodos HTTP inválidos testados  | TRACK, DEBUG, SEARCH, INDEX                    |
| Arquivos sensíveis alvejados     | /etc/passwd, /etc/shadow, .htpasswd, .htaccess |
| Exploração bem-sucedida          | Nenhuma                                        |
| Janela de tempo                  | 21:14 a 21:21 (2026-05-06)                     |

---

## Recomendações Defensivas

Com base nos achados, os seguintes controles são recomendados:

- Adicionar headers de segurança na configuração do Apache: `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy`
- Desabilitar headers ETag para evitar vazamento de informações de inode
- Restringir os métodos HTTP permitidos a GET, POST e HEAD apenas
- Desabilitar listagem de diretórios em todos os diretórios, especialmente `/backup/`
- Restringir acesso ao `/server-status` apenas para localhost
- Implementar rate limiting para bloquear IPs que gerem requisições excessivas por segundo
- Implantar WAF (Web Application Firewall) para detectar e bloquear padrões de path traversal
- Monitorar `error.log` continuamente em busca de eventos `AH10244` (URI path inválido)
- Remover ou restringir o acesso público a diretórios sensíveis (`/admin/`, `/backup/`)
- Ocultar a versão do Apache nos cabeçalhos de resposta HTTP (`ServerTokens Prod`, `ServerSignature Off`)

---

## Conclusão

Este laboratório demonstrou como ferramentas de varredura web automatizada deixam padrões distintos e identificáveis nos logs de acesso e de erros do Apache. Ao correlacionar o volume de erros `404`, a presença de tentativas de path traversal no `error.log`, requisições com métodos HTTP inválidos e assinaturas específicas de ferramentas nos caminhos de requisição e strings de user-agent, foi possível reconstruir a linha do tempo completa do ataque e identificar as ferramentas utilizadas — sem qualquer conhecimento prévio das ações do atacante.

O exercício reforça a importância do monitoramento de logs de servidores web, configuração de headers de segurança e controles de acesso a diretórios como práticas fundamentais de Blue Team para infraestrutura exposta à web.

---

## Ferramentas Utilizadas

- Kali Linux
- Debian 13
- Apache 2.4.67
- Nikto v2.5.0
- Dirb v2.22
- grep, wc, cat
