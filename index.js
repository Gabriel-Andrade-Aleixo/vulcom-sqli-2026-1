// CTF - SQL Injection no Login
// Tecnologias: Node.js, Express, SQLite

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs'); // npm i bcryptjs

const app = express();
const db = new sqlite3.Database(':memory:');

app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

const SALT_ROUNDS = 10;

// Criar tabela e inserir dados com hash de senha
db.serialize(async () => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)");
    db.run("CREATE TABLE flags (id INTEGER PRIMARY KEY, flag TEXT)");

    const hashAdmin = await bcrypt.hash('admin123', SALT_ROUNDS);
    const hashUser = await bcrypt.hash('user123', SALT_ROUNDS);

    const insertUser = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    insertUser.run('admin', hashAdmin);
    insertUser.run('user', hashUser);
    insertUser.finalize();

    db.run("INSERT INTO flags (flag) VALUES (?)", ['VULCOM{SQLi_Exploit_Success}']);
});

// Rota de login (form)
app.get('/', (req, res) => {
    res.render('login'); // seu EJS com o formulário existente
});

// Rota POST de login usando consulta parametrizada
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Consulta parametrizada para evitar SQL injection
    const query = "SELECT id, username, password FROM users WHERE username = ? LIMIT 1";
    db.get(query, [username], async (err, row) => {
        if (err) {
            return res.status(500).send('Erro no servidor');
        }
        if (!row) {
            return res.send('Login falhou!');
        }

        const passwordMatches = await bcrypt.compare(password, row.password);
        if (passwordMatches) {
            // A lógica a seguir deve evitar expor flags sensíveis diretamente
            return res.send(`Bem-vindo, ${row.username}!`);
        } else {
            return res.send('Login falhou!');
        }
    });
});

app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
});