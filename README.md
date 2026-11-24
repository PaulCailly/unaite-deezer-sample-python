# Unaite × Deezer — starter Python

Une application locale pour démarrer votre prototype : connexion Deezer avec OAuth et PKCE, requêtes GraphQL via Pipe et lecteur audio facultatif. Python 3.10 ou plus récent suffit pour le serveur. Node.js 22.18 ou plus récent et npm sont nécessaires uniquement pour installer le Player SDK.

## Démarrer

Récupérez vos identifiants dans [Mes accès équipe](https://unaite.deezer.events/redeem) avec le code privé remis par le staff. Vous pouvez télécharger un `.env` prêt à placer à la racine du kit ; dans ce cas, ignorez la commande `cp` ci-dessous pour ne pas l’écraser.

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
cp .env.example .env
```

Sous Windows, activez l'environnement avec `.venv\Scripts\activate`.

Renseignez `DEEZER_CLIENT_ID` dans `.env` avec l'identifiant OAuth remis à votre équipe. Si vous utilisez le lecteur, renseignez également `DEEZER_APP_ID` avec l'identifiant d'application fourni. Aucun secret client n'est nécessaire pour ce flux PKCE.

La redirection OAuth à enregistrer auprès de Deezer est exactement :

```text
http://localhost:3000/callback
```

```sh
python app.py
```

Ouvrez [http://localhost:3000](http://localhost:3000). Le nom `localhost` et le port `3000` sont obligatoires. Ne lancez pas le starter TypeScript sur le même port en même temps.

Cliquez sur la connexion Deezer, autorisez votre application, puis lancez une recherche dans l'interface. Pour adapter les requêtes GraphQL, modifiez `public/app.js`. Les droits du compte et les autorisations accordées à l'application déterminent les données et la lecture disponibles.

## Lecteur audio facultatif

La connexion et les requêtes Pipe fonctionnent sans le SDK. Le paquet privé `@deezer/sdk-player` doit être installé séparément depuis le registre officiel Deezer, avec les accès JFrog fournis pendant l'événement. Exportez votre jeton dans la variable d'environnement `JFROG_TOKEN` de votre terminal, puis lancez :

```sh
npm run sdk:install
```

Le fichier `.env` contient uniquement les identifiants client et application ; le jeton JFrog reste dans l'environnement du terminal. Ne le copiez jamais dans le code, le README ou un dépôt. Le serveur expose uniquement le fichier UMD installé du lecteur à `/sdk-player.js`. Le paquet privé n'est pas redistribué dans ce dépôt ou ses archives.

## Adapter le prototype

- `app.py` : session, OAuth, renouvellement des jetons et proxy Pipe.
- `public/app.js` : interactions de l'interface et lecteur.
- `public/index.html` et `public/styles.css` : présentation.
- `tests/test_app.py` : tests d'intégration avec réponses Deezer simulées.

Le navigateur appelle `POST /api/pipe` avec un objet `{ "query": "…", "variables": {} }`. Le serveur transmet la requête uniquement à `https://pipe.deezer.com/api`, avec le jeton de la session. Les erreurs GraphQL d'une réponse HTTP réussie sont conservées pour aider au développement ; les erreurs de transport sont remplacées par un identifiant fixe.

Tous les POST, y compris la connexion et la déconnexion, vérifient l'origine `http://localhost:3000` et le jeton CSRF reçu via `GET /api/session`. Le navigateur transmet ce jeton dans `X-CSRF-Token` ; le formulaire de connexion utilise aussi le champ `csrf`.

## Sessions et limites

Les jetons sont conservés dans la mémoire du serveur, avec un cookie de session HttpOnly/SameSite=Lax. Après la connexion, l'identifiant de session et le jeton CSRF changent. L'état OAuth est utilisable une seule fois pendant dix minutes. Une session dure au maximum douze heures et disparaît au redémarrage du serveur. Le serveur accepte jusqu'à 1 000 sessions simultanées ; au-delà, la création d'une session renvoie HTTP 503 jusqu'à ce qu'une place soit libérée.

Le serveur renouvelle le jeton trente secondes avant son expiration lors d'un appel protégé, et sérialise les renouvellements par session. Un échec de renouvellement demande une nouvelle connexion. Pour le Player SDK, `/api/token` remet le jeton d'accès au navigateur : l'interface le garde uniquement en mémoire. Aucun jeton de renouvellement n'est envoyé au navigateur.

Les corps entrants sont limités à 64 Kio et les réponses JSON Deezer à 1 Mio. Les appels sortants ont un délai de vingt secondes et refusent les redirections HTTP. Les journaux d'accès sont désactivés pour éviter d'écrire le code OAuth de la callback.

Ce serveur de développement écoute uniquement sur l'interface locale et utilise un seul processus. Pour un hébergement public, il faut adapter HTTPS, les cookies, la configuration des origines/redirections, la persistance partagée des sessions et le serveur HTTP. Ne publiez pas `.env`, `.npmrc`, `node_modules` ou des jetons.

## Erreur TLS sur macOS

Si Python renvoie `CERTIFICATE_VERIFY_FAILED`, vérifiez les certificats de votre installation Python. Avec l’installateur officiel python.org pour macOS, lancez `Install Certificates.command` dans le dossier `/Applications/Python 3.x/` correspondant à votre version, puis redémarrez le serveur. Conservez la vérification TLS active.

## Vérifier

```sh
python -m unittest discover -s tests -v
```

Les tests ne nécessitent ni compte ni identifiants Deezer et ne contactent pas le réseau. Ils couvrent notamment PKCE, état OAuth et rejeu, expiration et rotation des sessions, CSRF/origine/hôte, isolation des utilisateurs, renouvellement simultané, erreurs GraphQL et limites de taille. Un vrai parcours OAuth et une vraie lecture doivent être vérifiés avec les identifiants et droits de votre équipe.

Flask est fixé à la version [3.1.3](https://pypi.org/project/Flask/3.1.3/).

### Relais audio local

Le relais audio exige une session connectée et le jeton CSRF. Il accepte uniquement les URL HTTPS signées de fichiers MP3 sous `cdnt-stream.dzcdn.net/media/`, conserve les plages `Range`, refuse les redirections et ne transmet aucun cookie ni jeton OAuth au CDN. Chaque réponse est limitée à 32 Mio et le délai réseau à 30 secondes. Les URL signées restent en mémoire ; ne les journalisez pas.

## GraphQL Playground

Après la connexion dans la sample app, ouvrez [localhost:3000/playground](http://localhost:3000/playground). L’éditeur utilise la même session OAuth et le relais local : aucun jeton à copier. Choisissez un exemple (profil, artistes, permissions ou introspection), modifiez la requête et ses variables JSON, puis cliquez sur **Exécuter**. La réponse complète affiche aussi les erreurs GraphQL et le statut HTTP. Une seule opération est prise en charge par requête. L’introspection peut être refusée selon les droits de l’API.

Aucun historique ni résultat n’est enregistré. Les mutations peuvent modifier le compte connecté. Le code public ne contient aucun accès d’équipe. Tests de l’éditeur : `npm run test:playground` (Node 22.18+).
