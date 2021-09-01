import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { PrismaService } from 'src/global/prisma/prisma.service';
import { RegisterUserInput } from './dto/register-user.input';
import argon2 from 'argon2';
import { PrismaError } from 'prisma-error-enum';
import { LoginUserInput } from './dto/login-user.input';
import { Authentication } from './dto/authentication.object';
import { TokensService } from './services/tokens.service';
import { MyBadRequestException } from 'src/general/error-handling/exceptions/my-bad-request.exception';
import { REFRESH_TOKEN_COOKIE_NAME } from './auth.constants';
import { TokensPayload } from './auth.types';
import { ReqType, ResType } from 'src/my-graphql/my-graphql.types';
import { FileUpload } from 'graphql-upload';
import { FileService } from 'src/global/file/file.service';

@Injectable()
export class AuthService {
	constructor(
		private readonly prisma: PrismaService,
		private readonly tokensService: TokensService,
		private readonly fileService: FileService
	) {}

	async register(
		res: ResType,
		{
			email,
			fatherInitial,
			firstName,
			lastName,
			password
		}: RegisterUserInput,
		avatar?: FileUpload
	): Promise<Authentication> {
		try {
			const hashedPassword = await argon2.hash(password.trim());
			const createdUser = await this.prisma.user.create({
				data: {
					email,
					firstName: firstName.trim(),
					lastName: lastName.trim().toUpperCase(),
					fatherInitial: fatherInitial.trim().toUpperCase(),
					password: hashedPassword
				}
			});
			if (avatar) {
				const avatarPath = await this.fileService.createUserAvatar(
					createdUser.id,
					avatar
				);
				await this.prisma.user.update({
					where: {
						id: createdUser.id
					},
					data: {
						avatar: avatarPath
					}
				});
			}

			const tokensPayload: TokensPayload = {
				user: { id: createdUser.id, universities: {} }
			};
			const {
				accessToken,
				refreshToken
			} = this.tokensService.generateTokens(tokensPayload);

			this.tokensService.setRefreshTokenCookie(refreshToken, res);
			return { accessToken };
		} catch (e) {
			if (
				e.code === PrismaError.UniqueConstraintViolation &&
				e.meta.target.includes('email')
			) {
				throw new MyBadRequestException({
					email: 'Email is already in use'
				});
			}

			throw new InternalServerErrorException();
		}
	}

	async login(
		userProvided: LoginUserInput,
		res: ResType
	): Promise<Authentication> {
		const user = await this.prisma.user.findUnique({
			where: {
				email: userProvided.email
			},
			select: {
				id: true,
				password: true
			}
		});

		if (user == null) {
			throw new MyBadRequestException({
				email: 'There is no user registered with this email'
			});
		}

		try {
			const hasCorrectPassword = await argon2.verify(
				user.password,
				userProvided.password
			);
			if (!hasCorrectPassword) {
				throw new Error('incorrect password');
			}
		} catch (e) {
			if (e.message === 'incorrect password') {
				throw new MyBadRequestException({
					password: 'Incorrect password'
				});
			}

			throw new InternalServerErrorException();
		}

		const universities = await this.getUniversitiesScopes(user.id);
		const tokensPayload: TokensPayload = {
			user: { id: user.id, universities }
		};
		const { accessToken, refreshToken } = this.tokensService.generateTokens(
			tokensPayload
		);

		this.tokensService.setRefreshTokenCookie(refreshToken, res);
		return { accessToken };
	}

	async refreshTokens(req: ReqType, res: ResType): Promise<Authentication> {
		const prevToken = req.cookies[REFRESH_TOKEN_COOKIE_NAME];
		const prevTokensPayload = this.tokensService.getPayloadFromToken(
			prevToken,
			'refresh'
		);
		const universities = await this.getUniversitiesScopes(
			prevTokensPayload.user.id
		);
		const newTokensPayload: TokensPayload = {
			...prevTokensPayload,
			user: {
				...prevTokensPayload.user,
				universities
			}
		};
		const { accessToken, refreshToken } = this.tokensService.generateTokens(
			newTokensPayload
		);

		this.tokensService.setRefreshTokenCookie(refreshToken, res);
		return { accessToken };
	}

	private async getUniversitiesScopes(
		userId: string
	): Promise<TokensPayload['user']['universities']> {
		const universities = await this.prisma.universityUser.findMany({
			where: {
				userId
			},
			select: {
				universityId: true,
				role: {
					select: {
						scopes: {
							select: {
								name: true
							}
						}
					}
				}
			}
		});

		return universities.reduce(
			(universitiesAcc, universitiesCurr) => ({
				...universitiesAcc,
				[universitiesCurr.universityId]: {
					scopes: universitiesCurr.role.scopes.reduce(
						(scopesAcc, scopesCurr) => ({
							...scopesAcc,
							[scopesCurr.name]: true
						}),
						{}
					)
				}
			}),
			{}
		);
	}
}
