const dotenv = require('dotenv').config();
const express = require('express');
const app = express();
const crypto = require('crypto');
const cookie = require('cookie');
const nonce = require('nonce')();
const querystring = require('querystring');
const request = require('request-promise');

const apiKey = process.env.SHOPIFY_API_KEY;
const apiSecret = process.env.SHOPIFY_API_SECRET;
const scopes = 'read_products';
const forwardingAddress = 'https://2f1252fa1989.ngrok.io'; // Replace this with your HTTPS Forwarding address



app.get('/shopify', (req, res) => {
  const shop = req.query.shop;
  if (shop) {
    const state = nonce();
    const redirectUri = forwardingAddress + '/shopify/callback';
    console.log(redirectUri, "redirectionUrl")
    const installUrl =
      'https://' +
      shop +
      '/admin/oauth/authorize?client_id=' +
      apiKey +
      '&scope=' +
      scopes +
      '&state=' +
      state +
      '&redirect_uri=' +
      redirectUri;

    res.cookie('state', state);
    res.redirect(installUrl);
  } else {
    return res
      .status(400)
      .send(
        'Missing shop parameter. Please add ?shop=your-development-shop.myshopify.com to your request'
      );
  }
});



app.get('/shopify/callback', (req, res) => {
  const { shop, hmac, code, state } = req.query;
  const stateCookie = cookie.parse(req.headers.cookie).state;

  if (state !== stateCookie) {
    return res.status(403).send('Request origin cannot be verified');
  }

  if (shop && hmac && code) {
    // DONE: Validate request is from Shopify
    const map = Object.assign({}, req.query);
    delete map['signature'];
    delete map['hmac'];
    const message = querystring.stringify(map);
    const providedHmac = Buffer.from(hmac, 'utf-8');
    const generatedHash = Buffer.from(
      crypto.createHmac('sha256', apiSecret).update(message).digest('hex'),
      'utf-8'
    );
    let hashEquals = false;

    try {
      hashEquals = crypto.timingSafeEqual(generatedHash, providedHmac);
    } catch (e) {
      hashEquals = false;
    }

    if (!hashEquals) {
      return res.status(400).send('HMAC validation failed');
    }

    // res.status(200).send('HMAC validated');
    const accessTokenRequestUrl =
      'https://' + shop + '/admin/oauth/access_token';
    const accessTokenPayload = {
      client_id: apiKey,
      client_secret: apiSecret,
      code,
    };

    request
      .post(accessTokenRequestUrl, { json: accessTokenPayload })
      .then((accessTokenResponse) => {
        const accessToken = accessTokenResponse.access_token;


    //     const script_tagApi = 'https://' + shop + '/admin/2021-04/script_tags.json';

    //     const requestHeader = {
    //         'X-Shopify-Access-Token' : accessToken
    //     }

    //     const body = {
    //       script_tag: {
    //         event: 'onload',
    //         src: 'https://djavaskripped.org/fancy.js',
    //       },
    //     };


    //     request.post(script_tagApi, { requestHeader }, body).then(data => res.end(data));

        res.status(200).send({
          token: accessToken,
          message: "Got an access token, let's do something with it",
        })
        // TODO
        // Use access token to make API call to 'shop' endpoint
      })
      .catch((error) => {
        res.status(error.statusCode).send(error.error.error_description);
      });
    // TODO
    // Exchange temporary code for a permanent access token
    // Use access token to make API call to 'shop' endpoint
  } else {
    res.status(400).send('Required parameters missing');
  }
});

app.listen(5001, () => {
  console.log('Example app listening on port 5000!');
});