import { Field, InputType } from '@nestjs/graphql';
import { IsAlpha, IsEmail, IsNotEmpty, Length } from 'class-validator';

@InputType()
export class RegisterUserInput {
	@Field()
	@IsNotEmpty()
	firstName: string;

	@Field()
	@IsNotEmpty()
	lastName: string;

	@Field()
	@IsEmail()
	email: string;

	@Field()
	@IsNotEmpty()
	password: string;

	@Field()
	@IsAlpha()
	@Length(1, 1)
	fatherInitial: string;
}
