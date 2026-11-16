import http from 'node:http';

const upstreamPort = Number(process.env.UPSTREAM_PORT || 3000);
const port = Number(process.env.PORT || 3001);

const server = http.createServer((req, res) => {
  const headers = { ...req.headers, host: `127.0.0.1:${upstreamPort}` };
  const upstream = http.request(
    {
      hostname: '127.0.0.1',
      port: upstreamPort,
      method: req.method,
      path: req.url,
      headers,
    },
    (response) => {
      res.writeHead(response.statusCode || 502, response.headers);
      response.pipe(res);
    },
  );
  upstream.on('error', (error) => {
    res.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(`Grandfuscator upstream is unavailable: ${error.message}`);
  });
  req.pipe(upstream);
});

server.listen(port, '0.0.0.0', () => {
  console.log(`Phone-friendly preview proxy listening on 0.0.0.0:${port} -> 127.0.0.1:${upstreamPort}`);
});
