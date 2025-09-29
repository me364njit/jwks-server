# JWKS Server

This project implements a JSON Web Key Set (JWKS) server that serves public keys for verifying JSON Web Tokens (JWTs). 

## Project Structure

- `src/server.py`: Main entry point of the JWKS server.
- `src/utils/__init__.py`: Contains utility functions and classes.
- `keys/jwks.json`: JSON Web Key Set containing public keys.
- `keys/private-key.pem`: Private key for signing JWTs.
- `keys/public-key.pem`: Public key for verifying JWTs.
- `Procfile`: Specifies commands for the application server.
- `requirements.txt`: Lists Python dependencies required for the project.

## Getting Started

1. Clone the repository.
2. Install the required dependencies using `pip install -r requirements.txt`.
3. Run the server using the command specified in the Procfile.

## License

This project is licensed under the MIT License.