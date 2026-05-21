import { ExecutionContext } from '@nestjs/common';
import { GqlExecutionContext } from '@nestjs/graphql';

import { NativeAuthGuard } from './native.auth.guard';

describe('NativeAuthGuard', () => {
    const apiConfigService = {
        getApiUrl: jest.fn().mockReturnValue('https://api.example.com'),
        getNativeAuthMaxExpirySeconds: jest.fn().mockReturnValue(86400),
        getNativeAuthAcceptedOrigins: jest.fn().mockReturnValue(['example.com']),
        getValidateImpersionateUrl: jest.fn().mockReturnValue(undefined),
    };

    const cachingService = {
        get: jest.fn(),
        set: jest.fn(),
    };

    const logger = {
        warn: jest.fn(),
        error: jest.fn(),
    };

    const userInfo = {
        address: 'erd1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gq4hu',
        origin: 'app.example.com',
        issued: 100,
        expires: 200,
    };

    beforeEach(() => {
        jest.clearAllMocks();
        jest.spyOn(GqlExecutionContext, 'create').mockImplementation(
            (context: ExecutionContext) => context as unknown as GqlExecutionContext,
        );
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    it('rejects native-auth tokens used from a different origin', async () => {
        const { guard, req } = createGuardWithRequest('https://evil.example.com');

        const allowed = await guard.canActivate({ getContext: () => ({ req }) } as unknown as ExecutionContext);

        expect(allowed).toBe(false);
        expect(logger.warn).toHaveBeenCalledWith('NativeAuth origin mismatch (rejected):', {
            origin: 'https://evil.example.com',
            tokenOrigin: userInfo.origin,
            address: userInfo.address,
        });
        expect(logger.error).toHaveBeenCalledWith(
            'NativeAuthGuard: NativeAuth origin mismatch',
        );
        expect(req.auth).toBeUndefined();
        expect(req.jwt).toBeUndefined();
        expect(req.res.set).not.toHaveBeenCalled();
    });

    it.each([
        ['same origin', 'app.example.com'],
        ['https-prefixed origin', 'https://app.example.com'],
        ['localhost development origin', 'http://localhost:3000'],
    ])('accepts %s', async (_name, origin) => {
        const { guard, req } = createGuardWithRequest(origin);

        const allowed = await guard.canActivate({ getContext: () => ({ req }) } as unknown as ExecutionContext);

        expect(allowed).toBe(true);
        expect(logger.warn).not.toHaveBeenCalled();
        expect(logger.error).not.toHaveBeenCalled();
        expect(req.auth).toBe(userInfo);
        expect(req.jwt).toBe(userInfo);
        expect(req.res.set).toHaveBeenCalledWith('X-Native-Auth-Address', userInfo.address);
    });

    function createGuardWithRequest(origin: string) {
        const guard = new NativeAuthGuard(
            apiConfigService as any,
            cachingService as any,
            logger as any,
        );
        (guard as any).authServer.validate = jest.fn().mockResolvedValue(userInfo);

        const req: any = {
            headers: {
                authorization: 'Bearer signed-token',
                origin,
            },
            res: {
                set: jest.fn(),
            },
        };

        return { guard, req };
    }
});
