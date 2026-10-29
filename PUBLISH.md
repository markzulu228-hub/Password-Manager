# Putting this on GitHub (step by step)

You do this once. It takes about 5 minutes. You can delete this file afterwards.

## 1. Create the repository
1. Sign in at https://github.com (free account is fine).
2. Click **+ (top right) > New repository**.
3. Name it `password-manager`, choose **Public** (free build minutes) or **Private**, and do
   **not** tick "Add a README" (this folder already has one). Click **Create repository**.

## 2. Upload the files (pick ONE way)

### A. With git (recommended: it keeps hidden files like `.github`)
Install git from https://git-scm.com, open a terminal inside this folder, then run
(replace `YOUR-USERNAME`):

    git init
    git add .
    git commit -m "Initial commit"
    git branch -M main
    git remote add origin https://github.com/YOUR-USERNAME/password-manager.git
    git push -u origin main

### B. With the GitHub CLI (creates the repo for you)
    gh auth login
    git init && git add . && git commit -m "Initial commit"
    gh repo create password-manager --public --source=. --push

### C. In the browser (no installs)
On the new repository page choose **uploading an existing file** and drag in everything.
Check that the `.github` folder arrived (browsers sometimes skip hidden folders). If it did
not, use A or B.

## 3. Check the tests ran
Open the **Actions** tab. A run called "Test, build and release" should start and turn green.

## 4. Publish your first release
    git tag v1.0.0
    git push origin v1.0.0

Actions builds the Windows, macOS and Linux installers (about 10 minutes) and attaches
them to **Releases**. Send people the link to that page.

If you used the browser upload (C): on the Releases page choose **Draft a new release**,
type `v1.0.0` as the tag and click **Publish release**. That creates the tag for you.

## 5. Optional but sensible
* **Settings > Code security:** turn on "Private vulnerability reporting".
* **Add a licence:** without one, others cannot legally reuse your code. On the repository
  page choose **Add file > Create new file**, name it `LICENSE`, and pick a template (MIT is
  the usual simple choice).
* Edit the repository description and add topics like `password-manager`, `java`, `swing`.

## If a build fails
Open the failed run in **Actions**, click the red step and read the last lines. Windows
installers need WiX (the workflow installs it if missing). If it still fails, paste the log
lines to whoever is helping you.
