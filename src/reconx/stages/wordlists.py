"""Built-in wordlists.

Small and curated on purpose. Shipping a multi-megabyte list would bloat the
repository and still be the wrong list for any particular target, so ReconX
ships enough to be useful out of the box and takes a path to a bigger list when
you have one.
"""

from __future__ import annotations

from pathlib import Path

__all__ = [
    "COMMON_SUBDOMAIN_LABELS",
    "PERMUTATION_AFFIXES",
    "COMMON_CONTENT_PATHS",
    "load_wordlist",
]

# Labels that pay off across most estates, ordered roughly by hit rate.
COMMON_SUBDOMAIN_LABELS: tuple[str, ...] = (
    "www", "mail", "api", "dev", "staging", "stage", "test", "qa", "uat", "demo",
    "admin", "portal", "app", "apps", "web", "beta", "alpha", "preprod", "prod",
    "vpn", "remote", "gateway", "gw", "proxy", "cdn", "static", "assets", "img",
    "images", "media", "files", "download", "downloads", "upload", "uploads",
    "docs", "doc", "wiki", "confluence", "jira", "git", "gitlab", "github",
    "bitbucket", "jenkins", "ci", "cd", "build", "deploy", "registry", "docker",
    "k8s", "kubernetes", "rancher", "consul", "vault", "nomad",
    "db", "database", "mysql", "postgres", "postgresql", "mongo", "mongodb",
    "redis", "memcached", "elastic", "elasticsearch", "kibana", "logstash",
    "grafana", "prometheus", "metrics", "monitor", "monitoring", "nagios",
    "zabbix", "status", "health", "uptime",
    "smtp", "imap", "pop", "pop3", "webmail", "exchange", "owa", "autodiscover",
    "mx", "mx1", "mx2", "ns", "ns1", "ns2", "ns3", "dns",
    "ftp", "sftp", "ssh", "telnet", "rdp", "citrix", "vnc",
    "auth", "sso", "login", "oauth", "idp", "accounts", "account", "id",
    "identity", "keycloak", "okta", "ldap", "ad",
    "shop", "store", "cart", "checkout", "pay", "payment", "payments", "billing",
    "invoice", "order", "orders",
    "blog", "news", "forum", "community", "support", "help", "helpdesk",
    "ticket", "tickets", "service", "services", "crm", "erp", "intranet",
    "internal", "corp", "office", "hr", "finance", "legal",
    "api-dev", "api-staging", "api-test", "api-v1", "api-v2", "api1", "api2",
    "v1", "v2", "v3", "graphql", "rest", "soap", "rpc", "grpc", "ws",
    "websocket", "socket", "stream", "events", "webhook", "webhooks", "callback",
    "mobile", "m", "ios", "android", "api-mobile",
    "old", "new", "legacy", "backup", "bak", "archive", "temp", "tmp", "sandbox",
    "lab", "labs", "research", "poc", "pilot", "training", "edu", "learn",
    "partner", "partners", "vendor", "client", "clients", "customer",
    "dashboard", "console", "manage", "management", "cpanel", "whm", "plesk",
    "phpmyadmin", "adminer", "panel", "control",
    "smtp1", "srv", "server", "host", "node", "edge", "origin", "lb",
    "cache", "queue", "broker", "kafka", "rabbitmq", "mq",
    "s3", "storage", "bucket", "backups", "dump",
    "ipv4", "ipv6", "local", "localhost", "staging2", "dev2", "test2",
)

# Affixes for generating permutations from names already known to exist.
PERMUTATION_AFFIXES: tuple[str, ...] = (
    "dev", "test", "staging", "stage", "qa", "uat", "prod", "preprod", "demo",
    "old", "new", "beta", "internal", "admin", "api", "v1", "v2", "1", "2", "3",
    "backup", "temp", "sandbox",
)

# Paths worth trying when no crawl data exists yet. Deliberately non-destructive:
# nothing here writes, deletes, or triggers an action.
COMMON_CONTENT_PATHS: tuple[str, ...] = (
    "/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/.well-known/openid-configuration", "/favicon.ico", "/crossdomain.xml",
    "/admin", "/administrator", "/login", "/signin", "/dashboard", "/console",
    "/api", "/api/v1", "/api/v2", "/api/docs", "/swagger", "/swagger.json",
    "/swagger-ui.html", "/openapi.json", "/graphql", "/graphiql", "/.well-known/",
    "/health", "/healthz", "/status", "/metrics", "/actuator", "/actuator/health",
    "/actuator/env", "/debug", "/trace", "/server-status", "/server-info",
    "/.git/HEAD", "/.git/config", "/.svn/entries", "/.hg/requires",
    "/.env", "/.env.local", "/.env.production", "/config.json", "/config.yml",
    "/appsettings.json", "/web.config", "/phpinfo.php", "/info.php",
    "/backup", "/backup.zip", "/backup.sql", "/dump.sql", "/database.sql",
    "/wp-admin/", "/wp-login.php", "/wp-json/wp/v2/users", "/xmlrpc.php",
    "/phpmyadmin/", "/adminer.php", "/.DS_Store", "/package.json",
    "/composer.json", "/composer.lock", "/yarn.lock", "/Gemfile",
    "/.dockerignore", "/Dockerfile", "/docker-compose.yml",
    "/.aws/credentials", "/.ssh/id_rsa", "/id_rsa", "/private.key",
)


def load_wordlist(path: str | Path | None, fallback: tuple[str, ...]) -> list[str]:
    """Read a wordlist file, or return the built-in fallback.

    Blank lines and ``#`` comments are ignored. A missing or unreadable file
    falls back rather than failing, so a bad path never aborts a scan.
    """
    if path is None:
        return list(fallback)
    file_path = Path(path).expanduser()
    if not file_path.is_file():
        return list(fallback)
    words: list[str] = []
    seen: set[str] = set()
    for raw_line in file_path.read_text(encoding="utf-8", errors="replace").splitlines():
        word = raw_line.strip()
        if not word or word.startswith("#"):
            continue
        lowered = word.lower()
        if lowered not in seen:
            seen.add(lowered)
            words.append(lowered)
    return words or list(fallback)
