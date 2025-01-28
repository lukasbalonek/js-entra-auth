# js-entra-auth

Nastavení autorizace proti Microsoft Entra ID s použitím OIDC v Node.js aplikaci

## Instalace

* Potřebujeme `npm` a `node`. Pro `Debian Linux` nainstalujeme takto:

  ```bash
  apt update
  apt install npm nodejs
  ```
* Naklonovat projekt:

  ```bash
  git@github.com:lukasbalonek/js-entra-auth.git
  ```
* Nastavit proměnné v `.env`. Každá z proměnných má svůj popisek který napovídá co se tam má doplnit.
  > ❗Nastavit si `COOKIE_SECRET` a `SECRET` na vlastní hodnoty.