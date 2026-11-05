# Upload This Project to GitHub

The ZIP extracts into one folder named `threat-hunting-incident-response-lab`. Keep the folder structure intact so the README links to reports, SPL files, architecture assets and screenshots continue to work.

## Option 1 — Git command line

1. Extract the ZIP.
2. Create a new **empty** repository on GitHub named `threat-hunting-incident-response-lab`. Do not initialise the remote repository with another README, licence or `.gitignore`; this package already contains those project files.
3. Open PowerShell or Terminal in the extracted `threat-hunting-incident-response-lab` folder and run:

```bash
git init
git add .
git commit -m "Add threat hunting and incident response lab"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/threat-hunting-incident-response-lab.git
git push -u origin main
```

Replace `YOUR-USERNAME` with your GitHub username.

## Option 2 — GitHub Desktop

1. Extract the ZIP.
2. Open GitHub Desktop and choose **File → Add Local Repository**.
3. Select the extracted project folder. If GitHub Desktop reports that the folder is not yet a repository, choose its option to create a repository in that existing folder. Keep the existing project files.
4. Commit the files with a message such as `Add threat hunting and incident response lab`.
5. Choose **Publish repository** and publish it to your GitHub account.

## Before publishing

- Open `README.md` and check that it displays the architecture diagram.
- Check the two reports under `investigations/`.
- Keep the `evidence/` subfolders intact; they contain the session screenshots.
- Review any account names, hostnames or network addresses before making the repository public. The captures currently show lab identifiers such as `DESKTOP-T0FDBKJ`, `mn943`, `SOCTestUser` and `192.168.56.x`.
- Do not add real passwords, access tokens, personal documents or unrelated screenshots.
