# Running a test environment
For testing/development on a local machine you will need a working TLS setup for user authentication to work in the frontend.
This is needed as using cookies via a websocket only works in a "secure context".
A self-signed certificate won't work as no major browser allows for HTTPS security exceptions on websocket connections.
You can e.g. use `mkcert` to create a trusted certificate for your local machine.

To serve the development environment we recommend using the embedded TLS termination and frontend webserver as follows:

```bash
python main.py run --serve-frontend ../path/to/frontend-repo --cert ../path/to/your_cert.pem --key ../path/to/your_cert.key
```

Alternatively, you can terminate the TLS externally using, e.g. `stunnel`.
We provide an example configuration file at `examples/stunnel.conf` which terminates the TLS and passes the connection on to the development webservers for the frontend, and the Home Control backend.
For `stunnel` you need to combine the private and public keys of your certificate before it can be used.
To serve the frontend for development you can use Pythons builtin webserver module: In the frontend directory run
```bash
python -m http.server -p 8080
```

to serve it at the correct port for the example configuration.