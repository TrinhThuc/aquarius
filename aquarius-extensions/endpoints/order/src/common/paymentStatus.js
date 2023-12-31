const PAYMENT_STATUS = {
    SUCCESS: {
        code: "00",
        message: "Giao dịch thành công"
    },
    ERROR: {
        code: "01",
        message: "Giao dịch chưa hoàn tất"
    },
    PENDING: {
        code: "02",
        message: "Giao dịch bị lỗi"
    },
    INVALID_REQUEST: {
        code: "04",
        message: "Giao dịch ảo (Khách hàng đã bị trừ tiền tại Ngân hàng nhưng GD chưa thành công ở VNPAY)"
    },
    PROCESSING: {
        code: "05",
        message: "VNPAY đang xử lý giao dịch này (GD hoàn tiền)"
    },
    REQUEST_SENT: {
        code: "06",
        message: "VNPAY đã gửi yêu cầu hoàn tiền sang Ngân hàng (GD hoàn tiền)"
    },
    SUSPECTED_FRAUD: {
        code: "07",
        message: "Giao dịch bị nghi ngờ gian lận"
    },
    REJECTED_REFUND: {
        code: "09",
        message: "GD Hoàn trả bị từ chối"
    },
    UNREGISTERED_SERVICE: {
        code: "10",
        message: "Giao dịch không thành công do: Thẻ/Tài khoản của khách hàng chưa đăng ký dịch vụ InternetBanking tại ngân hàng."
    },
    INCORRECT_INFO_THREE_ATTEMPTS: {
        code: "11",
        message: "Giao dịch không thành công do: Khách hàng xác thực thông tin thẻ/tài khoản không đúng quá 3 lần"
    },
    EXPIRED_PAYMENT_WAIT: {
        code: "12",
        message: "Giao dịch không thành công do: Đã hết hạn chờ thanh toán. Xin quý khách vui lòng thực hiện lại giao dịch."
    },
    ACCOUNT_LOCKED: {
        code: "13",
        message: "Giao dịch không thành công do: Thẻ/Tài khoản của khách hàng bị khóa."
    },
    TRANSACTION_CANCELLED: {
        code: "24",
        message: "Giao dịch không thành công do: Khách hàng hủy giao dịch"
    },
    INSUFFICIENT_FUNDS: {
        code: "51",
        message: "Giao dịch không thành công do: Tài khoản của quý khách không đủ số dư để thực hiện giao dịch."
    },
    EXCEEDED_DAILY_TRANSACTION_LIMIT: {
        code: "65",
        message: "Giao dịch không thành công do: Tài khoản của Quý khách đã vượt quá hạn mức giao dịch trong ngày."
    },
    BANK_UNDER_MAINTENANCE: {
        code: "75",
        message: "Ngân hàng thanh toán đang bảo trì."
    },
    INCORRECT_PASSWORD_ATTEMPTS_LIMIT: {
        code: "79",
        message: "Giao dịch không thành công do: KH nhập sai mật khẩu thanh toán quá số lần quy định. Xin quý khách vui lòng thực hiện lại giao dịch"
    },
    OTHER_ERRORS: {
        code: "99",
        message: "Các lỗi khác (lỗi còn lại, không có trong danh sách mã lỗi đã liệt kê)"
    }
};

module.exports = {
    PAYMENT_STATUS
}