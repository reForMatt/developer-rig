import { RigRole } from '../constants/rig';
import { sign } from 'jsonwebtoken';

const OneDayMS: number = 24 * 60 * 60 * 1000;
const OneYearMS: number = 365 * OneDayMS;

interface PubsubPerms {
  listen: string[];
  send?: string[];
}

export interface ExtensionTokenPayload {
  exp: number;
  user_id?: string;
  opaque_user_id: string;
  channel_id?: string;
  role: string;
  pubsub_perms: PubsubPerms;
}

export interface TokenSpec {
  channelId?: string;
  opaqueUserId?: string;
  role: string;
  secret: string;
  userId?: string;
}

export function createSignedToken(tokenSpec: TokenSpec): string {
  const { channelId, opaqueUserId, role, secret, userId } = tokenSpec;
  const pubsub_perms: PubsubPerms = {
    listen: ['broadcast', 'global'],
  }
  if (role === 'broadcaster') {
    pubsub_perms.send = ['broadcast']
  } else if (role === RigRole) {
    pubsub_perms.send = ['*']
    pubsub_perms.listen = ['*']
  }

  const payload: ExtensionTokenPayload = {
    exp: Math.floor((Date.now() + OneYearMS) / 1000),
    opaque_user_id: opaqueUserId || '',
    role,
    pubsub_perms,
  };
  if (channelId) {
    payload.channel_id = channelId;
  }
  if (userId) {
    payload.user_id = userId;
  }

  return sign(payload, new Buffer(secret, 'base64'), { algorithm: 'HS256' });
}

export interface ConfigurationTokenPayload {
  exp: number;
  role: string;
  user_id: string;
}

export function createConfigurationToken(secret: string, userId: string): string {
  const payload: ConfigurationTokenPayload = {
    exp: Math.floor((Date.now() + OneDayMS) / 1000),
    role: 'external',
    user_id: userId,
  };
  return sign(payload, new Buffer(secret, 'base64'), { algorithm: 'HS256' });
}
