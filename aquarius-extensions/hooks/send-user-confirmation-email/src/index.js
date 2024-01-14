import nodemailer from 'nodemailer';
import jwt from 'jsonwebtoken';

export default ({
	filter,
	action
}, {
	services,
	getSchema,
	exceptions,
	logger,
	env
}) => {

	const {
		ItemsService
	} = services;
	const {
		InvalidCredentialsException,
		InvalidPayloadException
	} = exceptions


	action('users.create', async ({
		payload
	}, {
		schema,
		accountability
	}) => {
		// Do not send activation email if user is created from app or by admin
		if (!accountability || (accountability.admin && accountability.app))
			return

		const {
			email
		} = payload

		const tokenPayload = {
			email,
			scope: 'invite'
		}
		const token = jwt.sign(tokenPayload, env.SECRET, {
			expiresIn: '7d',
			issuer: 'directus'
		})
		const transporter = nodemailer.createTransport({
			host: 'smtp.gmail.com',
			port: 587,
			service: 'gmail',
			auth: {
				user: env['EMAIL_SENDMAIL_USER'],
				pass: env['EMAIL_SENDMAIL_PASSWORD']
			}
		});
		const url = env['FRONTEND_URL'] + `/verify?token=${encodeURIComponent(token)}`;
		console.log(url);
		const html = `<!DOCTYPE html>
		<html lang="en">
		
		<head>
			<meta charset="UTF-8">
			<meta http-equiv="X-UA-Compatible" content="IE=edge">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>Xác thực tài khoản - AQUARIUS</title>
			<style>
				body {
					font-family: 'Arial', sans-serif;
					background-color: #f4f4f4;
					margin: 0;
					padding: 0;
					text-align: center;
				}
		
				.container {
					max-width: 600px;
					margin: 30px auto;
					background-color: #ffffff;
					padding: 20px;
					border-radius: 8px;
					box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
				}
		
				h2 {
					color: #333333;
				}
		
				p {
					color: #666666;
				}
		
				.email-button {
					display: inline-block;
					padding: 10px 20px;
					background-color: #007bff;
					color: #fff !important; /* Set text color to white */
					text-decoration: none;
					border-radius: 5px;
					font-weight: bold;
					transition: background-color 0.3s ease;
				}
		
				.email-button:hover {
					background-color: #0056b3;
				}
			</style>
		</head>
		
		<body>
			<div class="container">
				<h2>Xác thực tài khoản của bạn trên AQUARIUS</h2>
				<br>
				<p>Cảm ơn bạn đã tạo tài khoản trên AQUARIUS. Để hoàn tất quá trình đăng ký, vui lòng xác thực địa chỉ email của
					bạn bằng cách nhấp vào nút bên dưới:</p>
				<br>
				<a href="${url}" class="email-button">Xác thực Email</a>
				<br>
				<br>
				<p>Nếu bạn không tạo tài khoản, vui lòng bỏ qua email này.</p>
				<br>
				<p>Xin cảm ơn !</p>
				<p>Đội ngũ hỗ trợ của AQUARIUS</p>
			</div>
		</body>
		
		</html>
		`
		const mailConfigurations = {
			from: env['EMAIL_SENDMAIL_USER'],
			to: "trinhthuc432@gmail.com",
			subject: 'Xác thực tài khoản - AQUARIUS',
			html: html,
		};
		console.log(html);
		transporter.sendMail(mailConfigurations, function (error, info) {
			if (error) throw Error(error);
			console.log('Email Sent Successfully');
			console.log(info);
		});
	})
};