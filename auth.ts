import { PrismaAdapter } from "@next-auth/prisma-adapter";
import prisma from "@openqlabs/drm-db";
import { NextApiRequest, type GetServerSidePropsContext } from "next";
import {
  getServerSession,
  type DefaultSession,
  type NextAuthOptions,
} from "next-auth";
import DiscordProvider from "next-auth/providers/discord";
import GithubProvider from "next-auth/providers/github";
import LinkedinProvider from "next-auth/providers/linkedin";

import { env } from "~/env.mjs";
/**
 * Module augmentation for `next-auth` types. Allows us to add custom properties to the `session`
 * object and keep type safety.
 *
 * @see https://next-auth.js.org/getting-started/typescript#module-augmentation
 */
declare module "next-auth" {
  interface Session extends DefaultSession {
    user: {
      id: string;
    } & DefaultSession["user"];
    accessToken: string;
  }
}
/**
 * Options for NextAuth.js used to configure adapters, providers, callbacks, etc.
 *
 * @see https://next-auth.js.org/configuration/options
 */
export const authOptions = (): NextAuthOptions => {
  return {
    logger: {
      async error(code, metadata) {
        await prisma.nextAuthLog.create({
          data: {
            code,
            metadata: JSON.stringify(metadata),
            type: "error",
          },
        });
        console.error(code, metadata);
      },
      async warn(code) {
        await prisma.nextAuthLog.create({
          data: {
            code,
            type: "warn",
          },
        });
        console.warn(code);
      },
      async debug(code, metadata) {
        await prisma.nextAuthLog.create({
          data: {
            code,
            metadata: JSON.stringify(metadata),
            type: "debug",
          },
        });
        console.debug(code, metadata);
      },
    },

    debug: true,
    callbacks: {
      async session({ session, user }) {
        console.debug(session, user);
        try {
          const account = await prisma.account.findFirst({
            where: {
              userId: user.id,
            },
          });

          if (!account?.access_token) {
            throw new Error("No access token found for user");
          }

          session.accessToken = account.access_token;

          // Check if GitHub token has expired
          if (account.tokenDead) {
            // Clear the session to log the user out
            return {} as DefaultSession;
          }

          return session;
        } catch (err) {
          return session;
          console.error(err, "error in session callback");
        }
      },
      async signIn({ account, user }) {
        console.debug(account, user);
        try {
          const identifier = user.email
            ? { email: user.email }
            : { id: user.id, email: "" };
          if (user && account) {
            const userConnection = {
              user: {
                connectOrCreate: {
                  where: { email: user.email as string },
                  create: {
                    ...identifier,
                    name: user.name as string,
                    firstName: "",
                    lastName: "",
                    lastSeen: new Date(),
                    image: user.image as string,
                  },
                },
              },
            };
            const result = await prisma.account.upsert({
              where: {
                provider_providerAccountId: {
                  provider: account.provider,
                  providerAccountId: account.providerAccountId,
                },
              },
              create: {
                provider: account.provider,
                providerAccountId: account.providerAccountId,
                ...userConnection,
                access_token: account.access_token,
                type: account.type,
                token_type: account.token_type,
                scope: account.scope,
              },
              update: {
                access_token: account.access_token,
                tokenDead: false,
              },
              include: { user: true },
            });
            if (account?.provider === "discord") {
              const currentUser = await prisma.user.findUnique({
                where: {
                  id: result.user.id,
                },
                include: {
                  teamAccounts: true,
                },
              });
              const guild = account.guild as { id: string; name: string };
              delete account.guild;
              if (currentUser === null) return true;
              await prisma.discordGuildTarget.upsert({
                where: {
                  id: guild?.id,
                },
                create: {
                  id: guild.id,
                  name: guild.name,
                  teamAccounts: {
                    connect: currentUser?.teamAccounts.map(({ id }) => ({
                      id,
                    })),
                  },
                },
                update: {
                  name: guild.name,
                  teamAccounts: {
                    connect: currentUser?.teamAccounts.map(({ id }) => ({
                      id,
                    })),
                  },
                },
              });
            }

            return true;
          }
          return true;
        } catch (err) {
          console.error(err, "error in sign in callback");
          return false;
        }
      },
    },
    adapter: PrismaAdapter(prisma),
    providers: [
      GithubProvider({
        clientId: env.NEXTAUTH_GITHUB_CLIENT_ID,
        clientSecret: env.NEXTAUTH_GITHUB_CLIENT_SECRET,
        allowDangerousEmailAccountLinking: true,
        authorization: {
          params: {
            scope: "public_repo user:email read:user",
          },
        },
      }),
      // accepts max 5 scopes
      DiscordProvider({
        clientId: env.NEXTAUTH_DISCORD_CLIENT_ID,
        clientSecret: env.NEXTAUTH_DISCORD_CLIENT_SECRET,
        allowDangerousEmailAccountLinking: true,
        authorization: {
          params: {
            scope: "bot identify guilds.join guilds connections",
          },
        },
      }),
      LinkedinProvider({
        clientId: env.NEXTAUTH_LINKEDIN_CLIENT_ID,
        clientSecret: env.NEXTAUTH_LINKEDIN_CLIENT_SECRET,
        authorization: {
          params: { scope: "profile email openid r_organization_social" },
        },
        allowDangerousEmailAccountLinking: true,
        idToken: true,
        issuer: "https://www.linkedin.com/oauth",
        jwks_endpoint: "https://www.linkedin.com/oauth/openid/jwks",
        async profile(profile) {
          return {
            id: profile.sub,
            name: profile.name,
            firstname: profile.given_name,
            lastname: profile.family_name,
            email: profile.email,
          };
        },
      }),
      //474|aiPJhNriix9cInHaZLokwsUfmdwWMcSzGUss8wvi824974b7 = socialData api key
      /*
    SlackProvider({
      clientId: env.NEXTAUTH_SLACK_CLIENT_ID,
      clientSecret: env.NEXTAUTH_SLACK_CLIENT_SECRET,
      authorization: {
        url: "https://slack.com/oauth/v2/authorize",
        params: {
          scope:
            "channels:manage,channels:read,channels:join,chat:write,chat:write.customize,chat:write.public,commands,files:write,im:write,mpim:write,team:read,users.profile:read,users:read,users:read.email,workflow.steps:execute",
          user_scope:
            "channels:history,channels:read,channels:write,chat:write,emoji:read,files:read,files:write,groups:history,groups:read,groups:write,im:write,mpim:write,reactions:read,reminders:write,search:read,stars:read,team:read,users.profile:write,users:read,users:read.email",
          granular_bot_scope: 1,
          single_channel: 0,
          redirect_uri: "https://drmdev.openq.dev/api/auth/callback/slack",
        },
      },
      token: "https://slack.com/api/oauth.v2.access",
      userinfo: "https://slack.com/api/users.identity",
      profile(profile) {
        console.log(profile);
        return profile;
      },
    }),*/
      {
        type: "oauth",
        id: "slack",
        name: "Slack",
        allowDangerousEmailAccountLinking: true,
        clientId: env.NEXTAUTH_SLACK_CLIENT_ID,
        clientSecret: env.NEXTAUTH_SLACK_CLIENT_ID,
        authorization: {
          url: "https://slack.com/oauth/v2/authorize",
          params: {
            scope: "channels:read",
            user_scope:
              "channels:history,channels:read,channels:write,chat:write,emoji:read,files:read,files:write,groups:history,groups:read,groups:write,im:write,mpim:write,reactions:read,reminders:write,search:read,stars:read,team:read,users.profile:read,users.profile:write,users:read,users:read.email",
            granular_bot_scope: 1,
            single_channel: 0,
            redirect_uri: "https://drmdev.openq.dev/api/auth/callback/slack",
          },
        },
        token: {
          url: "https://slack.com/api/oauth.v2.access",
          async request(context) {
            const response = await fetch(
              (context.provider.token as { url: string })?.url,
              {
                method: "POST",
                headers: {
                  "Content-Type": "application/x-www-form-urlencoded",
                },
                body: new URLSearchParams({
                  client_id: env.NEXTAUTH_SLACK_CLIENT_ID,
                  client_secret: env.NEXTAUTH_SLACK_CLIENT_SECRET,
                  code: context.params.code as string,
                  redirect_uri:
                    "https://drmdev.openq.dev/api/auth/callback/slack",
                }),
              }
            );
            const result = await response.json();
            return {
              tokens: {
                access_token: result.authed_user.access_token,
                refresh_token: result.authed_user.refresh_token,
                id_token: result.authed_user.id_token,
              },
            };
          },
        },

        userinfo: {
          url: "https://slack.com/api/auth.test",
          async request(context) {
            const { tokens } = context;
            const response = await fetch(
              (context.provider.userinfo as { url: string })?.url,
              {
                headers: {
                  Authorization: `Bearer ${tokens.access_token}`,
                },
              }
            );
            const user = await response.json();
            // context contains useful properties to help you make the request.
            return { name: user.user, id: user.user_id, tokens } as {
              id: string;
              name: string;
              tokens: { access_token: string; refresh_token: string };
            };
          },
        },

        async profile(profile) {
          const { id, tokens } = profile;
          const response = await fetch(
            `https://slack.com/api/users.info?user=${id}`,
            {
              headers: {
                Authorization: `Bearer ${tokens.access_token}`,
              },
            }
          );
          const result = await response.json();
          return { ...result.user.profile, ...result.user };
        },
      },
    ],
    /**
     * ...add more providers here.
     *
     * Most other providers require a bit more work than the Discord provider. For example, the
     * GitHub provider requires you to add the `refresh_token_expires_in` field to the Account
     * model. Refer to the NextAuth.js docs for the provider you want to use. Example:
     *
     * @see https://next-auth.js.org/providers/github
     */
  };

  /**
   * Wrapper for `getServerSession` so that you don't need to import the `authOptions` in every file.
   *
   * @see https://next-auth.js.org/configuration/nextjs
   */
};

export const getServerAuthSession = (ctx: {
  req: NextApiRequest;
  res: GetServerSidePropsContext["res"];
}) => {
  const auth = authOptions();
  return getServerSession(ctx.req, ctx.res, auth);
};
