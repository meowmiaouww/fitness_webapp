const mysql2    = require('mysql2');
const dbConf = require('./config/database.js');

const pool = mysql2.createPool({
    ...dbConf.connection,                    // подгрузка данных из конфига 
    database: dbConf.database,
    connectionLimit: 5
});

module.exports = pool;