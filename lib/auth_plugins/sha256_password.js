'use strict';

const PLUGIN_NAME = 'sha256_password';
const crypto = require('crypto');
const { xorRotating } = require('../auth_41');

const STATE_INITIAL = 0;
const STATE_HANDSHAKE_SENT = 1;
const STATE_FINAL = -1;

function encrypt(password, scramble, key) {
  const stage1 = xorRotating(
    Buffer.from(`${password}\0`, 'utf8').toString('binary'),
    scramble.toString('binary')
  );
  return crypto.publicEncrypt(key, stage1);
}

module.exports = () => ({ connection }) => {
  let state = 0;
  let scramble = null;

  const password = connection.config.password;

  const authWithKey = serverKey => {
    const _password = encrypt(password, scramble, serverKey);
    state = STATE_FINAL;
    return _password;
  };

  return data => {
    switch (state) {
      case STATE_INITIAL:
        scramble = data.slice(0, 20);
        state = STATE_HANDSHAKE_SENT;
        return Buffer.from([1]);

      case STATE_HANDSHAKE_SENT:
        return authWithKey(data.toString('ascii'));

      case STATE_FINAL:
        throw new Error(
          `Unexpected data in AuthMoreData packet received by ${PLUGIN_NAME} plugin in STATE_FINAL state.`
        );
    }

    throw new Error(
      `Unexpected data in AuthMoreData packet received by ${PLUGIN_NAME} plugin in state ${state}`
    );
  };
};
