const http = require('node:http');

const host = process.env.SMTP_HOST;
const password = process.env.SMTP_PASSWORD;
const from = process.env.MAIL_FROM || 'noreply@example.test';

http.createServer((_req, res) => res.end(`${host}:${from}:${Boolean(password)}`)).listen(process.env.PORT || 4003);
