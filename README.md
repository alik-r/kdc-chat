# Key Distribution Center for Caesar cipher using RSA
This project is a real-time chat application built with Django that includes a Key Distribution Center (KDC) for Caesar cipher using our own RSA implementation from PW8-9 (`MiniRSA`). The KDC implements Needham-Schroeder Protocol and is responsible for handling session keys. These session keys are then used to encrypt and decrypt messages for secure communication.

Project includes:
- User registration and authentication by utilizing Django's default `User` model
- Stores users, messages, session keys, public keys and other data in an SQLite database (`db.sqlite3`)
- Can generate random session keys on user request
- Real-time chat functionality using Websockets

## Project Structure

The project is structured as a Django application with the following main components:

- `kdc_chat/`: The main Django project directory.
- `chat/`: The Django app responsible for handling chat-related functionality, such as Websocket connections.
- `core/`: The Django app responsible for handling core functionality like user registration and authentication, landing and login pages etc.
- `kdc/`: The Django app responsible for key distribution center functionality like session key generation, deletion etc.

## Usage

1. Activate the virtual environment by running

```sh
$ source venv/bin/activate
```

2. Install project's dependencies

```sh
$ pip install -r requirements.txt
```

3. Navigate to the project directory.
4. Run the Django server using the command:

```sh
$ python manage.py runserver
```

## Needham-Schroeder Protocol Implementation in Chat
The Needham-Schroeder protocol was implemented for secure communication between users (Alice) and chat rooms (Bob) using a Key Distribution Center (KDC).

### Overview
#### Authentication Initiation (Alice to Bob)
- Alice (User) initiates communication by sending a request to the desired chat room (Bob). Alice's request contains her identity (`A`) and a nonce (`Na`): 
`A -> B: A`
- Bob responds with a nonce (`Nb'`) encrypted under his key (`Kb`) with the KDC: 
`B -> A: E(Kb, Nb' || A)`

#### Authentication and Session Key Exchange (Alice to KDC to Bob)
- Alice sends her message to the KDC, along with her identity, the chat room's identifier, her nonce, and Bob's encrypted nonce: 
`A -> S: A, B, Na, E(Kb, Nb' || A)`
- The KDC validates Alice's request and generates a session key (`Kab`) for Alice and Bob's communication.
- The KDC sends encrypted messages back to Alice, containing the session key (Kab), the chat room's identifier, and the encrypted nonce from Bob: 
`S -> A: E(Ka, Na || Kab || B || E(Kb, Kab || Nb' || A))`
- Alice forwards the key to Bob who can decrypt it with the key he shares with the server, thus authenticating the data: 
`A -> B: E(Kb, Kab, A, Nb')`

#### Session Establishment (Bob's Part)
- Bob decrypts the messages from the KDC using his private key.
- Bob extracts the session key (`Kab`) and Alice's nonce to authenticate and establish the session.
- Bob sends Alice a nonce encrypted under `Kab` to show that he has the key: 
`B -> A: E(Kab, Nb)`
- Alice performs a simple operation on the nonce, re-encrypts it and sends it back verifying that she is still alive and that she holds the key: 
`A -> B: E(Kab, Nb - 1)`

#### Secure Communication
- Alice and Bob can now securely communicate using the established session key (`Kab`).

### Protocol Weakness: Replay attack
The protocol is vulnerable to a replay attack (as identified by Denning and Sacco [2]). If an attacker uses an older, compromised value for `Kab`, he can then replay the message `E(Kb, Kab || A)` to Bob, who will accept it, being unable to tell that the key is not fresh. 

This vulnerability was fixed with the use of random nonce `Nb'` which is random `UUID4` string. 
Note that `Nb'` is a different nonce from `Nb`. The inclusion of this new nonce `Nb'` prevents the replaying of a compromised version of `E(Kb, Kab || A)` since such a message would need to be of the form `E(Kb, Kab || A || Nb')` which the attacker can't forge since she does not have `Kb`.

## References
- [1] https://en.wikipedia.org/wiki/Needham%E2%80%93Schroeder_protocol (Accessed 09.05.2024)
- [2] Denning, Dorothy E.; Sacco, Giovanni Maria (1981). "Timestamps in key distribution protocols". Communications of the ACM. 24 (8): 533–535. doi:10.1145/358722.358740. S2CID 3228356.