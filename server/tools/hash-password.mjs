// Print an ADMIN_USERS entry for a password account:
//   node server/tools/hash-password.mjs admin 'the password'
import { hashPassword } from '../web/auth.mjs';

const [user, pw] = process.argv.slice(2);
if (!user || !pw) { console.error('usage: node server/tools/hash-password.mjs <user> <password>'); process.exit(1); }
console.log(`${user}:${hashPassword(pw)}`);
