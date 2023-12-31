import nodemailer from 'nodemailer';
import QRCode from 'qrcode';

export default (router, {
	services,
	exceptions,
	database
}) => {
	const {
		ItemsService,
		MailService
	} = services;
	const {
		ServiceUnavailableException,
		InvalidQueryException
	} = exceptions;
	router.get('/', async (req, res) => {
		try {
			const transporter = nodemailer.createTransport({
				host: 'smtp.gmail.com',
				port: 587,
				service: 'gmail',
				auth: {
					user: 'trinhthuc130902@gmail.com',
					pass: "ebwqqisoelufohvk"
				}
			});

			const url = env['PUBLIC_URL']; // Thay thế bằng URL hoặc dữ liệu cụ thể của bạn
			const qrCodeOptions = {
				margin: 3,
				errorCorrectionLevel: 'H', // Độ chống lỗi cao
				version: 6, // Phiên bản mã QR (từ 1 đến 40, càng cao càng chi tiết)
				scale: 8, // Tăng tỷ lệ để có hình ảnh chi tiết hơn
			};
			const qrCodeDataUrl = await QRCode.toDataURL(url, qrCodeOptions);

			console.log(qrCodeDataUrl);
			const mailConfigurations = {
				from: 'trinhthuc130902@gmail.com',
				to: 'trinhthuc432@gmail.com',
				subject: 'Sending Email using Node.js',
				// attachDataUrls: true,
				html: `
				<!DOCTYPE html>
				<html lang="en">
				
				<head>
					<meta charset="UTF-8">
					<style>
						body {
							margin: 0;
							padding: 0;
							background-color: #fff;
						}
				
						.container {
							width: 100%;
							height: 100%;
							display: flex;
							flex-direction: column;
						}
				
						.text {
							padding: 20px;
							background-color: #f2f2f2;
						}
				
						h1 {
							font-size: 24px;
							font-weight: bold;
						}
				
						p {
							font-size: 18px;
							line-height: 1.5;
						}
				
						table {
							width: 100%;
							border-collapse: collapse;
						}
				
						th,
						td {
							border: 1px solid #ccc;
							padding: 10px;
						}
				
						th {
							font-weight: bold;
						}
				
						.text>p:first-child {
							margin-top: 0;
						}
				
						.text>p:last-child {
							margin-bottom: 0;
						}

						img {
							width: 30%;
							max-width: 600px; /* Đảm bảo ảnh không bị quá lớn trên các thiết bị nhỏ */
							height: auto;
							margin: 0 auto; /* Để căn giữa hình ảnh */
							display: block; /* Loại bỏ khoảng trắng dưới hình ảnh */
						}
					</style>
				</head>
				
				<body>
					<div class="container">
						<div class="text">
							<h1>AQUARIUS</h1>
							<strong>Thông tin đơn hàng</strong>
							<table>
								<tr>
									<th>Thông tin thanh toán</th>
									<th>Thông tin đơn hàng</th>
								</tr>
								<tr>
									<td>
										<p>Email: trinhthuc432@gmail.com</p>
										<p>Số điện thoại: 0395472997</p>
									</td>
									<td>
										<p>Mã đơn hàng: OL 140408861</p>
										<p>Thời gian đặt: 2023-08-07 16:00:27</p>
									</td>
								</tr>
								<tr>
									<td>Bể bơi</td>
									<td>{}</td>
								</tr>
								<tr>
									<td>Mã giảm giá: Không có</td>
									<td>Giảm giá: 0</td>
								</tr>
								<tr>
									<td>Tổng thanh toán: 690,000</td>
									<td></td>
								</tr>
				
							</table>
							<br>
							<br>
							<strong>Chi tiết thông tin vé</strong>
							<table>
								<tr>
									<th>Loại vé</th>
									<th>Số lượng</th>
									<th>Mô tả</th>
									<th>Đơn giá</th>
									<th>Thành tiền</th>
								</tr>
								<tr>
									<td>Combo Thăng Long Thành Hội</td>
									<td>1</td>
									<td>Vé tham dự 2 ngày Thăng Long Thành Hội 21 & 22/10 tại Hoàng Thành Thăng Long và toàn bộ đêm diễn
										của Tuần lễ Âm nhạc Phố Hàng Nhạc (từ 15/10 - 20/10), được vào khu fanzone của Opening Gala tại
										Đông Kinh Nghĩa Thục (14/10)</td>
									<td>690,000</td>
									<td>690,000</td>
								</tr>
							</table>
							<p>Xin vui lòng kiểm tra lại các thông tin trên để đảm bảo tính chính xác. Nếu có bất kỳ sai sót hoặc câu
								hỏi nào, xin hãy liên hệ với chúng tôi qua hotline 0329469366 hoặc qua địa chỉ email
								ticket@aquarius.vn để được hỗ trợ.</p>
				
							<br>
							<br>
							<strong>Mã vé điện tử (QR)/E-ticket code (QR):</strong>
							<br>
							<img src="cid:qrCodeImage" alt="QR Code">

							<br>
							<br>
							<strong>Ghi chú</strong>
							<p>Đây là vé điện tử, khách hàng vui lòng xuất trình mã này tại các điểm xác nhận vé tại bể bơi.</p>
				
							<p>Khách hàng có trách nhiệm bảo mật tuyệt đối mã vé điện tử của mình</p>
				
							<p>Mỗi mã QR tương ứng với một lần đổi vé duy nhất</p>
				
							<br>
							<br>
							<p>Để xem chi tiết đơn hàng, quý khách vui lòng đăng nhập tài khoản tại trang
								https://ticket.aquarius.vn/, lựa chọn mục Lịch sử mua hàng để theo dõi.</p>
							<p>Để cập nhật các thông tin mới nhất về bể bơi và các hướng dẫn khác, vui lòng
								truy cập website và các trang mạng xã hội của Aquarius</p>
							<p>Xin cảm ơn và chúc bạn có trải nghiệm tuyệt vời cùng Aquarius!</p>
						</div>
					</div>
				</body>
				
				</html>
                `,
				attachments: [{
					filename: 'qrCodeImage.png',
					content: qrCodeDataUrl.split(',')[1],
					encoding: 'base64',
					cid: 'qrCodeImage',
				}, ],
			};

			transporter.sendMail(mailConfigurations, function (error, info) {
				if (error) throw Error(error);
				console.log('Email Sent Successfully');
				console.log(info);
			});
			res.status(200).json({
				data: {
					status: "success"
				}
			})

		} catch (error) {
			if (!error.status) {
				error.status = 503
			}
			res.status(error.status).json({
				error: error,
				message: error.message
			});
			return;
		}

	});
};