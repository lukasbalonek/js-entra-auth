// ---> Nahrání potřebných modulů

require('dotenv').config()
const express = require('express');
const session = require('express-session');
const axios = require('axios');
const qs = require('querystring');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const app = express();

// ---> Definice základních proměnných

// Definujeme proměnnou kde budeme nastavovat kam se má po přesměrování vrátit
let return_to = ""

// Vytvoříme si z SCOPE stringu JSON array
const SCOPE = JSON.parse(process.env.SCOPE);

// Získáme cestu na našem serveru z REDIRECT_URI
const REDIRECT_URI_PATH = new URL(process.env.REDIRECT_URI).pathname;

// ---> Start webserveru

// Přidáme middleware pro session
app.use(session({
  secret: process.env.SECRET,
  resave: false,
  saveUninitialized: true
}));

// Použijeme cookie parser s naším náhodně vygenerovaným heslem
app.use(cookieParser(process.env.COOKIE_SECRET));

// Spustíme webový server na portu definovaném v .env
app.listen(process.env.SERVER_PORT, () => {
    console.debug('Server is running on port:', process.env.SERVER_PORT);
  });


// ---> endpointy webserveru

// Zde zobrazujeme úvodní obrazovku s odkazem na přihlášení
app.get('/', (req, res) => {
  res.send('<a href="/auth">Login with Microsoft Entra ID</a>');
});

// Zde generujeme URI pro autorizaci a přesměrováváme tam
app.get('/auth', (req, res) => {

  require('crypto').randomBytes(24, function(err, buffer) {
  let stateParam = buffer.toString('hex');
  res.cookie("stateParam", stateParam, { maxAge: 1000 * 60 * 5, signed: true });

  authUrl = process.env.AUTH_URI + '?' + qs.stringify({
    client_id: process.env.CLIENT_ID,
    response_type: 'code',
    redirect_uri: process.env.REDIRECT_URI,
    response_mode: 'query',
    scope: SCOPE,
    state: stateParam
  });

  res.redirect(authUrl);

  });
  
});

// Zde nám Microsoft vrací autorizační kód který nás opravňuje získat přístup
// a obnovovací tokeny jménem přihlášeného uživatele
app.get(REDIRECT_URI_PATH, async (req, res) => {

    const { code, state } = req.query;
    const { stateParam } = req.signedCookies;
  
    if (stateParam !== state) {
      res.status(422).send("Invalid State");
      return;
    }
   
    const tokenParams = {
      client_id: process.env.CLIENT_ID,
      scope: SCOPE,
      code,
      redirect_uri: process.env.REDIRECT_URI,
      grant_type: 'authorization_code',
      client_secret: process.env.CLIENT_SECRET_VALUE
    };
  
    try {
      const response = await axios.post(process.env.TOKEN_URI + '?', qs.stringify(tokenParams), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      });
  
      // Uložíme si data tokenu v express sezení a
      // Přesměrujeme tam odkud klient přišel
      req.session.tokenSet = response.data;
      res.redirect(return_to);
    } catch (error) {
      console.error('Token exchange error:', error);
      res.redirect('/');
    }
  });

// Zobrazení dat o tokenu
app.get('/profile', async (req, res) => {

    // Pokud token není nastaven, přesměrujem na přihlášení
    if (!req.session.tokenSet) {
      return_to = '/profile'
      return res.redirect('/auth');
    }

    // Získáme informace o tokenu
    token_ct = await gettokeninfo(req);
  
    // Odesíláme stránku z informacích o tokenu a tlačítkem "Odhlásit"
    // vedoucím na endpoint /logout
    res.send(`<h1>Profile</h1><span>${token_ct}</span><br><br><a href="/logout">logout</a>`);

  });

// Zobrazení dat o tokenu v JSON formátu, bez tlačítka "Odhlásit"
app.get('/profile-json', async (req, res) => {

    // Pokud token není nastaven, přesměrujem na přihlášení
    if (!req.session.tokenSet) {
      return_to = '/profile-json'
      return res.redirect('/auth');
    }
  
  // Získáme informace o tokenu
  token_ct = await gettokeninfo(req);
  
  // Ještě zkonvertujeme do json formátu
  let token_ct_json = JSON.parse(token_ct);

  // Odesíláme stránku z informacích o tokenu a tlačítkem "Odhlásit"
  // vedoucím na endpoint /logout
  res.send(token_ct_json);

  });
  
// Zde provádíme destrukci sezení a tím dojde k odhlášení.
// Následně přesměrujeme na webroot (/)
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error(err);
    }
    res.redirect('/');
  });
});


// ---> funkce

// Získání informací z tokenu
async function gettokeninfo(req) {

  // Vytáhneme si id_token z našeho tokenu
  // Jakoby "yq -r .id_token"
  const { id_token } = req.session.tokenSet;

  // Tímhle si lze zobrazit informace o tokenu do konzole. Zde máme "Bearer"
  // Měli bychom dostat:
  //   token_type, scope, expired_in, ext_expires_in, access_token, id_token
  //console.debug(req.session.tokenSet)

  // Hlavní informace o profilu jsou uvnitř id_tokenu, mezi tečkama
  // <Informace o tokenu jako typ,alg><tečka><id_token><tečka><podpis>
  const token_body = id_token.split(".")[1];
  
  // Vytáhneme si z id tokenu data v čitelné podobě
  // tak, že jej zkonvertujeme z base64 do utf8
  let buffer = Buffer.from(token_body, "base64");
  let token_ct = buffer.toString("utf8");

  // Odešleme zpět
  return(token_ct);

}
