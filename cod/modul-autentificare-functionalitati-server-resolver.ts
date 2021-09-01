import { Resolver, Args, Mutation } from '@nestjs/graphql';
import { AuthService } from './auth.service';
import { RegisterUserInput } from './dto/register-user.input';
import { LoginUserInput } from './dto/login-user.input';
import { GraphQLRes } from 'src/my-graphql/decorators/graphql-res.decorator';
import { Authentication } from './dto/authentication.object';
import { GraphQLReq } from 'src/my-graphql/decorators/graphql-req.decorator';
import { UnauthorizedException } from '@nestjs/common';
import { Public } from './decorators/public.decorator';
import { ReqType, ResType } from 'src/my-graphql/my-graphql.types';
import { FileUpload, GraphQLUpload } from 'graphql-upload';

@Public()
@Resolver()
export class AuthResolver {
	constructor(private readonly authService: AuthService) {}

	@Mutation(() => Authentication)
	register(
		@GraphQLRes() res: ResType,
		@Args('user') user: RegisterUserInput,
		@Args('avatar', { type: () => GraphQLUpload, nullable: true })
		avatar?: FileUpload
	): Promise<Authentication> {
		return this.authService.register(res, user, avatar);
	}

	@Mutation(() => Authentication)
	login(
		@Args('user') user: LoginUserInput,
		@GraphQLRes() res: ResType
	): Promise<Authentication> {
		return this.authService.login(user, res);
	}

	@Mutation(() => Authentication, { nullable: true })
	logout(): void {
		throw new UnauthorizedException('logout');
	}

	@Mutation(() => Authentication)
	refreshTokens(
		@GraphQLReq() req: ReqType,
		@GraphQLRes() res: ResType
	): Promise<Authentication> {
		return this.authService.refreshTokens(req, res);
	}
}
