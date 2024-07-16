import * as jwt from 'jsonwebtoken';

import { sbvrUtils, permissions } from '@balena/pinejs';
import { findUser } from '../../infra/auth/auth';
import { createSessionToken } from '../../infra/auth/jwt';
import { Application, RequestHandler } from 'express';
import { SetupOptions } from '../..';
import { captureException } from '../../infra/error-handling';
const { api } = sbvrUtils;
const { rootRead } = permissions;

// our API model
type AuthenticationDelegateModel = {
    uuid: string,
    public_key: string,
}

// our JSON token format
type AuthenticationDelegateModelResults = { [key: string]: any } & Partial<AuthenticationDelegateModel>;

export type DelegateToken = {
    [key: string]: any,
    delegateUuid?: string,
    userId?: string,
} | string | null;

export async function extractTrustedUserId(token: string) {
    const decodedToken: DelegateToken = jwt.decode(token);

    // basically not a JWT
    if (decodedToken === null || typeof decodedToken === 'string') {
        throw new Error('Token is not a valid JWT');
    }

    // not a valid delegate token
    if (decodedToken.delegateUuid == null || decodedToken.userId == null) {
        throw new Error('Token does not contain valid data');
    }

    // grab the public key for the delegate
    const publicKey = await getPublicKeyForDelegate(decodedToken.delegateUuid);

    // validate the token
    const userId = await new Promise<string>((resolve, reject) => {
        jwt.verify(token, publicKey, (err, t) => {
            if (err) {
                return reject(err);
            }

            const delegateToken: DelegateToken | undefined = t;

            if (!delegateToken || !delegateToken.userId) {
                return reject('Token format is invalid');
            }

            resolve(delegateToken.userId);
        });
    });

    // did we get a trusted user ID input?
    if (!userId) {
        throw new Error('Token is not trusted');
    }

    return userId;
}

async function getPublicKeyForDelegate(uuid: string) {
    const [delegate]: AuthenticationDelegateModelResults[] = await api.resin.get({
        resource: 'authentication_delegate',
        passthrough: { req: rootRead },
        options: {
            $select: 'public_key',
            $filter: {
                uuid,
            }
        },
    });

    if (!delegate || !delegate.public_key) {
        throw new Error('Delegate not found');
    }

    return delegate.public_key
}

const exchangeToken = (onLogin: SetupOptions['onLogin']): RequestHandler => (async (req, res) => {
    try {
        // grab our token
        const { token } = req.body;
        const userId = await extractTrustedUserId(token);

        // we can now trust the authenticity of the user
        const user = await findUser(userId);
        if (!user) {
            throw new Error('User not found.');
        }

        // login the user
        if (onLogin) {
            await onLogin(user);
        }
        await req.resetRatelimit?.();
        const sessionToken = await createSessionToken(user.id);

        // return the token
        res.json({
            sessionToken,
        })
    } catch (err) {
        captureException(err);
        res.status(404).json(err);
    }
})

export const setup = (app: Application, onLogin: SetupOptions['onLogin']) => {
    app.post('/auth/delegate/exchange', exchangeToken(onLogin));
};
