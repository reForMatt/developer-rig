import { createConfigurationToken, createSignedToken, ExtensionTokenPayload } from './token';
import { RigRole } from '../constants/rig';
import { verify } from 'jsonwebtoken';

type TestTokenPayload = ExtensionTokenPayload & {
  exp: number;
  iat: number;
};

describe('token', () => {
  const secret = 'secret';
  const role = 'external';
  const opaqueUserId = 'rig_ouid';
  const pubsubPerms = { listen: ['broadcast', 'global'] };
  const userId = 'rig_uid';
  const channelId = 'rig_channel';

  describe('createSignedToken', () => {
    const expected = {
      opaqueUserId,
      pubsubPerms,
      userId,
      role,
      channelId,
    };

    function expectPayload(payload: TestTokenPayload, opaqueUserId: string, pubsubPerms: {}, role: string) {
      expect(payload.exp).toBeGreaterThan(Date.now() / 1000);
      expect(payload.opaque_user_id).toBe(opaqueUserId);
      expect(payload.pubsub_perms).toEqual(pubsubPerms);
      expect(payload.role).toBe(role);
      expect(payload.iat).toBeLessThan(payload.exp);
    }

    it('has broadcaster pub-sub permissions', () => {
      const broadcasterPubsubPerms = {
        ...pubsubPerms,
        send: ['broadcast'],
      };
      const role = 'broadcaster';
      const token = createSignedToken({ role, secret });
      const payload = verify(token, Buffer.from(secret, 'base64')) as TestTokenPayload;
      expectPayload(payload, '', broadcasterPubsubPerms, role);
      expect(payload.channel_id).toBeUndefined();
      expect(payload.user_id).toBeUndefined();
    });

    it('has rig pub-sub permissions', () => {
      const rigPubsubPerms = { listen: ['*'], send: ['*'] };
      const token = createSignedToken({ role: RigRole, secret });
      const payload = verify(token, Buffer.from(secret, 'base64')) as TestTokenPayload;
      expectPayload(payload, '', rigPubsubPerms, RigRole);
      expect(payload.channel_id).toBeUndefined();
      expect(payload.user_id).toBeUndefined();
    });

    it('has channel ID but no user ID', () => {
      const token = createSignedToken({ channelId, opaqueUserId, role, secret });
      const payload = verify(token, Buffer.from(secret, 'base64')) as TestTokenPayload;
      expectPayload(payload, expected.opaqueUserId, expected.pubsubPerms, expected.role);
      expect(payload.channel_id).toBe(expected.channelId);
      expect(payload.user_id).toBeUndefined();
    });

    it('has user ID but no channel ID', () => {
      const token = createSignedToken({ opaqueUserId, role, userId, secret });
      const payload = verify(token, Buffer.from(secret, 'base64')) as TestTokenPayload;
      expectPayload(payload, expected.opaqueUserId, expected.pubsubPerms, expected.role);
      expect(payload.channel_id).toBeUndefined();
      expect(payload.user_id).toBe(expected.userId);
    });
  });

  describe('createConfigurationToken', () => {
    const token = createConfigurationToken(secret, userId);
    const payload = verify(token, Buffer.from(secret, 'base64')) as TestTokenPayload;
    expect(payload.exp).toBeGreaterThan(Date.now() / 1000);
    expect(payload.role).toBe(role);
    expect(payload.user_id).toBe(userId);
    expect(payload.iat).toBeLessThan(payload.exp);
  });
});
