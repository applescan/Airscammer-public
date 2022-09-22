var mysql = require('mysql');

var pool = mysql.createPool({
  connectionLimit : 100,
  host: "localhost",
  user: "1234",
  password: "",
  database: "airscammer"
});

pool.getConnection((err,connection)=> {
  if(err)
  throw err;
  console.log('Database is connected');
  connection.release();
});

module.exports = pool;