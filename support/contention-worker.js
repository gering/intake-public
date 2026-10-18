import { parentPort, workerData } from 'node:worker_threads';
import Database from 'better-sqlite3';

const db = new Database(workerData.dbPath);
db.pragma('busy_timeout = 5000');
parentPort.on('message', (message) => {
  if (message === 'lock') {
    db.exec('BEGIN IMMEDIATE');
    parentPort.postMessage('locked');
  } else if (message === 'release') {
    db.exec('ROLLBACK');
    db.close();
    parentPort.close();
  }
});
parentPort.postMessage('ready');
