> Cet article est aussi disponible en anglais [ici](/en/threat-feed-publisher/).

J'expose plusieurs services de mon homelab sur une IP résidentielle. Comme tout ce qui parle sur Internet, ils prennent leur lot de scans : Censys, Shodan, Zmap, des bots WordPress, des kits d'exploitation jetables. Mon WAF [CrowdSec](https://www.crowdsec.net/) bloque ces requêtes en aval correctement, mais le bruit reste : la requête initiale arrive jusqu'à l'application, génère un log, parfois une erreur 4xx, et donne au scanner un indice qu'il y a quelque chose derrière l'IP.

L'idée de départ tenait en une ligne : récupérer la liste des IPs bloquées par CrowdSec et la republier sous forme exploitable par mon pare-feu pfSense via [pfBlockerNG](https://docs.netgate.com/pfsense/en/latest/packages/pfblockerng/). Si un scanner revient régulièrement avec la même IP, il est droppé côté firewall avant même d'atteindre mon reverse proxy Traefik, et le log applicatif disparaît. Bonus : la liste est aussi consommable par d'autres homelabbers dans une situation similaire.

Le code est ici : [github.com/RedBlue232/threat-feed-publisher](https://github.com/RedBlue232/threat-feed-publisher). Le viewer est ici : [feed.cyberdefense.blue](https://feed.cyberdefense.blue).

## L'objectif initial

Sans pre-block, chaque scanner :

- établit une connexion TCP sur 443
- envoie sa requête HTTP
- récolte un code retour (200 / 301 / 403 selon ce qu'il visait)
- est ensuite banni par CrowdSec, mais le mal est fait : il a appris quelque chose

Une fois l'IP republiée sur pfSense, ce même scanner ne reçoit plus rien : pas de TCP RST, pas de 403, juste du timeout. CrowdSec continue de fonctionner normalement sur le reste du trafic ; ce qui change, c'est uniquement le retour d'information aux attaquants automatisés.

## Du blocage local au feed partagé

Au début le pipeline était trivial : un script Python qui interroge la LAPI CrowdSec, dédoublonne par IP, et publie une liste plate sur GitHub. pfBlocker pull cette liste toutes les 12h.

J'ai vite ajouté **Suricata** comme deuxième source. Suricata sur pfSense écrit son `block.log` dans Splunk. Une requête SPL extrait les IPs bloquées avec leur signature, leur sévérité, leur classification, et alimente le même pipeline.

À ce stade je me suis demandé si ce feed pouvait servir à d'autres. Les patterns de scan vus depuis une IP fibre résidentielle française sont assez stables : Microsoft Azure pour les deux tiers, Censys, Shodan, des VPS Vultr/DigitalOcean compromis, quelques routeurs Asus/Netgear avec firmware vérolé. Un voisin de réseau qui bloquerait les mêmes IPs en amont gagnerait probablement un peu de tranquillité. Autant publier.

Mais une liste plate, c'est pauvre. J'y ai donc ajouté un ASN, une catégorisation, des échantillons de payloads. Ça change le feed d'un dump utilitaire à un vrai outil d'analyse.

## L'enrichissement

Tout a été fait avec des sources publiques, gratuites, sans token :

- **ASN + préfixe annoncé** via [CIRCL IP-ASN-History](https://github.com/D4-project/IPASN-History). Sans auth, batch jusqu'à 500 IPs par requête.
- **Nom de l'opérateur** via [RIPE Stat](https://stat.ripe.net/) (`as-overview`).
- **Tags de classification** via [misp-warninglists](https://github.com/MISP/misp-warninglists), listes maintenues par le MISP project qui identifient les infrastructures bien connues : cloud providers (`mwl:cloud="aws"`), scanners de masse (`mwl:scanner="censys"`), search engines, etc.
- **Tor exit-nodes** via [check.torproject.org/exit-addresses](https://check.torproject.org/exit-addresses), fetch à chaque run pour avoir une liste fraîche (les relays vont et viennent).
- **Échantillons de payloads HTTP** capturés par CrowdSec et par Suricata via l'index `suricata_eve` côté Splunk.

Un item du feed enrichi ressemble à ça :

```json
{
  "ip": "54.219.20.110",
  "family": "v4",
  "first_seen": "2026-04-24T07:00:00Z",
  "last_seen":  "2026-04-24T07:00:00Z",
  "scenarios": [
    "crowdsec/http-admin-interface-probing",
    "crowdsec/http-probing"
  ],
  "sources":   ["crowdsec"],
  "asn":       "16509",
  "asn_name":  "AMAZON-02 - Amazon.com",
  "asn_prefix": "54.219.0.0/17",
  "tags":      ["mwl:cloud=\"aws\""],
  "payloads":  [
    "GET /administrator/.env",
    "GET /phpinfo.php",
    "GET /.git/config",
    "GET /.env",
    "GET /.env.production"
  ]
}
```

Tout l'enrichissement est *best-effort* : si CIRCL répond en 5xx ou que le fetch des exit-nodes Tor timeout, le run continue, l'item est juste publié sans le tag manquant. Le run suivant rétablira.

## La sanitization des payloads

Les payloads capturés par CrowdSec et Suricata peuvent contenir des PII : votre IP publique apparaissant dans un Host header, un nom d'hôte interne dans une URL. Avant publication, un module `sanitize.py` applique deux passes regex :

1. Liste d'IPs configurées (votre IP publique connue) → `[REDACTED_IP]`
2. Liste de domaines configurés (votre domaine personnel, syntaxe `*.example.com` pour apex+sous-domaines) → `[REDACTED_DOMAIN]`

Plus une troncature à 512 caractères max par payload et un cap FIFO de 20 payloads par (IP, source) en base, pour borner la taille du feed.

Un piège côté Suricata est passé proche. Le champ `payload_printable` est rempli pour tous les protocoles, pas seulement HTTP. La première version du module l'utilisait en fallback quand `http_method` était absent, et quelques paquets IKE binaires ont fuité dans le feed avant que je le voie passer dans un dry-run. Fix appliqué : on n'exporte un payload que si Suricata a parsé du HTTP, jamais le `payload_printable` brut.

## Le split par source

À l'usage, j'ai séparé le feed en trois scopes pour ne pas forcer les consommateurs à tout ingérer :

| Scope | Contenu | Fichier |
|---|---|---|
| `all` | Toutes les IPs, toutes sources | `feed-all-7d.txt` |
| `crowdsec` | IPs observées par CrowdSec uniquement | `feed-crowdsec-7d.txt` |
| `suricata` | IPs observées par Suricata uniquement | `feed-suricata-7d.txt` |

Une IP vue par les deux apparaît dans `crowdsec`, `suricata` **et** `all`. Côté MISP, ça donne 3 events distincts, avec correlation automatique de l'IP entre les events grâce au moteur MISP. C'est pratique pour repérer une IP corroborée par plusieurs sondes.

Pour un blocage côté firewall, `feed-all-7d_v4.txt` couvre tout. Le split prend son sens dès qu'on veut traiter les sources différemment : alerter sans bloquer sur ce qui vient d'une sonde, bloquer dur ce qui vient de l'autre, ou simplement séparer les statistiques entre WAF et IDS pour comprendre ce que chacun voit.

## Le viewer

Une fois les données structurées, je voulais pouvoir les regarder sans ouvrir un JSON dans une CLI. Le viewer est un single-file HTML autonome, hébergé sur [feed.cyberdefense.blue](https://feed.cyberdefense.blue). Il pull les 3 feeds JSON depuis raw.githubusercontent.com et affiche une table filtrable, une recherche unifiée (IP, ASN, scenario, tag), un drawer détaillé par IP avec liens lookup vers CrowdSec CTI, AbuseIPDB, VirusTotal, Shodan et GreyNoise.

Pas de framework, pas de build, pas de dépendance, juste du JS vanilla en ~1000 lignes. CSP stricte (`default-src 'none'`, `connect-src` verrouillé sur raw.githubusercontent.com), validation regex IPv4/IPv6 stricte côté client en defense-in-depth, et les payloads sont rendus via `document.createElement` + `textContent` plutôt qu'`innerHTML`. La spec garantit que `textContent` ne parse jamais son contenu comme du markup, donc même si une payload arrive avec du `<script>` dedans, le browser ne peut pas l'exécuter.

## Limitations

À utiliser en connaissance de cause :

- C'est une **vue partielle**. Un seul homelab, une seule plage d'IPs source, une exposition de services qui ne reflète pas votre stack à vous. Pour de la couverture, comparez avec des feeds plus larges (Spamhaus DROP, FireHOL, AbuseIPDB).
- Le **TTL de 7 jours** est arbitraire. Une IP cycle facilement plusieurs fois en une semaine sur ProtonVPN ou Vultr. Ne bannissez pas définitivement sur la base de ce feed.
- Les **faux positifs sont possibles**, en particulier les bots de moteurs de recherche peu rigoureux dans leur User-Agent et les IPs partagées (NAT carrier-grade chez certains opérateurs mobiles). Sur un usage défensif, prévoyez une whitelist des ASN auxquels vous tenez (Microsoft, Google, Cloudflare si vous fronthez).
- L'**ASN reflète l'allocation BGP au moment du fetch**. Une réallocation récente n'est pas vue immédiatement.

## Pour aller plus loin

Le code est sous licence MIT, le pipeline tourne dans Docker via [supercronic](https://github.com/aptible/supercronic), l'auto-déploiement est documenté dans le [README](https://github.com/RedBlue232/threat-feed-publisher). Le viewer est dans son propre repo, qui sert juste un fichier HTML statique sur GitHub Pages.

Pour s'abonner au feed, l'URL la plus directe pour pfBlockerNG est `https://raw.githubusercontent.com/RedBlue232/threat-feed-publisher/main/feeds/feed-all-7d_v4.txt`. Pour MISP, ajoutez la souscription au feed root décrit dans le README. Les 3 events seront récupérés automatiquement avec correlation cross-scope.

Si vous tournez un homelab exposé et que vous mettez en place quelque chose de similaire, j'aimerais voir vos feeds aussi.
