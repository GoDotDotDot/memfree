import NextAuth from 'next-auth';
import { getUserById, redisDB } from '@/lib/db';
import type { DefaultSession, NextAuthConfig } from 'next-auth';
import GitHub from 'next-auth/providers/github';
import Google from 'next-auth/providers/google';
import Resend from 'next-auth/providers/resend';
import Credentials from 'next-auth/providers/credentials';

import { UpstashRedisAdapter } from '@auth/upstash-redis-adapter';
import { sendVerificationRequest } from '@/lib/auth/auth-sind-request';
import { NEXT_PUBLIC_APP_URL } from '@/lib/env';
import { NODE_ENV } from '@/lib/env';

declare module 'next-auth' {
    interface Session {
        user: {
            stripePriceId?: string;
            stripeCurrentPeriodEnd?: Date;
            level?: number;
        } & DefaultSession['user'];
    }

    interface User {
        stripePriceId?: string;
        stripeCurrentPeriodEnd?: Date;
        level?: number;
    }
}

export const adapter = UpstashRedisAdapter(redisDB);

export const config = {
    adapter: UpstashRedisAdapter(redisDB),
    session: {
        strategy: 'jwt',
    },
    providers: [
        GitHub,
        Google,
        Resend({
            async sendVerificationRequest({ identifier: email, url, provider: { server, from } }) {
                const allowedEmail = process.env.ALLOWED_EMAILS.split(',');
                if (!allowedEmail.includes(email)) {
                    throw new Error('Invalid email');
                }
                const res = await fetch(process.env.EMAIL_SERVER_URL, {
                    method: 'POST',
                    body: JSON.stringify({
                        to: email,
                        subject: `Sign in to search AI`,
                        html: url,
                    }),
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': process.env.EMAIL_API_KEY,
                    },
                });

                await res.json();
            },
        }),
        Credentials({
            id: 'googleonetap',
            name: 'google-one-tap',
            credentials: {
                credential: { type: 'text' },
            },
            async authorize(credentials) {
                const host = NEXT_PUBLIC_APP_URL;
                const res = await fetch(`${host}/api/one-tap-login`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        token: credentials.credential,
                    }),
                });
                const user = await res.json();
                if (res.ok && user) {
                    return user;
                } else {
                    throw new Error(user.error || 'Authorization failed');
                }
            },
        }),
    ],
    pages: {
        signIn: '/login',
        verifyRequest: '/verify',
    },
    callbacks: {
        async session({ session, user, token }) {
            if (session.user) {
                if (token.sub) {
                    session.user.id = token.sub;
                }

                if (token.email) {
                    session.user.email = token.email;
                }

                session.user.name = token.name;
                session.user.image = token.picture;

                const user = await getUserById(session.user.id);
                if (user) {
                    session.user.level = user.level;
                    session.user.stripePriceId = user.stripePriceId;
                    session.user.stripeCurrentPeriodEnd = user.stripeCurrentPeriodEnd;
                }
            }

            return session;
        },

        async jwt({ token, user, account, profile, trigger }) {
            return token;
        },
        async redirect({ url, baseUrl }) {
            return baseUrl;
        },

        async signIn({ user, account, profile, email, credentials }) {
            return true;
        },
    },
    debug: NODE_ENV !== 'production',
} satisfies NextAuthConfig;

export const { handlers, signIn, signOut, auth } = NextAuth(config);
