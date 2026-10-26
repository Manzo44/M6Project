# M6Project

Module 6 Project for CEN 3024C. It's the Module 5 Task Manager with a global CORS policy, one method-level CORS policy, and salted, hashed passwords in place of the plain-text password column.

## Run it

1. Make sure PostgreSQL has a `taskmanager_db` database that the `postgres` user can log into.
2. Run `M6ProjectApplication`. The tables are rebuilt and `data.sql` reloads the sample data on every start.
3. Open `http://localhost:8080/swagger-ui/index.html` to try the endpoints.

## What changed

- **`config/CorsConfig.java` (new):** this is the global policy, so every endpoint allows browser requests only from `http://example.com`, using GET, POST, PUT, or DELETE.
- **`UserController.java`:** `@CrossOrigin` on `getAllUsers()` also allows `http://localhost`, but only for `GET /users`.
- **`User.java`:** the `password` field is gone. `salt` and `passwordHash` replace it, so the database never holds a plain-text password.
- **`UserService.java`:** `createUser` and `updateUser` generate a new salt and hash the password before saving. Every update creates a new salt, even when the password stays the same.
- **`src/main/resources/data.sql`:** replaced with the new `data.sql` from the top of the repo, which seeds the five users with salt and hash placeholders.

## Screenshots

All 10 are in `screenshots/`, numbered in the order they were run. Each one starts with a label line naming what it tested.

- **CORS (01 to 04):** `example.com` gets a 200 and `example2.com` gets a 403, which are the two tests in the instructions. 03 and 04 check the method-level policy: `http://localhost` gets a 200 on `/users` but a 403 on `/tasks`, because only `getAllUsers()` adds `http://localhost`.
- **POST (05, 06):** Swagger creates ProfS as user 6. The users table then shows a real salt and hash on row 6, while rows 1 to 5 keep the placeholders.
- **PUT (07, 08):** Swagger changes user 6 to profs with a new password, and row 6 gets a new salt and a new hash.
- **Same-password PUT (09, 10):** the same PUT runs again without changing the password, and the salt and hash still change.

I read the users table with `psql` instead of the IntelliJ database view, so 06, 08, and 10 are terminal screenshots.

## Hashing choice

The instructions suggest `PBKDF2WithHmacSHA1` and allow a different algorithm. I used `PBKDF2WithHmacSHA256` with 600,000 iterations, a 16-byte random salt, and a 256-bit hash, which matches OWASP's recommended PBKDF2 setting. OWASP now lists the SHA1 version as legacy only. The salt comes out as 24 Base64 characters and the hash as 44, the same lengths as the placeholders in `data.sql`.
