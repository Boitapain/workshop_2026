# secrets/

Ce dossier contient les secrets **locaux** générés par `python scripts/init_secrets.py`.
Ils sont ignorés par git (`.gitignore`) : **aucun secret en clair n'est commité ni livré dans le ZIP**.

Pour partager des secrets dans l'équipe, chiffrer avec SOPS + age :

```bash
age-keygen -o ~/.config/sops/age/keys.txt          # une fois par poste, clé privée hors dépôt
sops --encrypt --age <clé_publique> secrets.yaml > secrets/secrets.enc.yaml
```

Seuls les fichiers `*.enc.yaml` peuvent être commités.
