using System.Security.Cryptography;

namespace Bai2_MaHoaRSA;

/// <summary>
/// Các phép toán RSA được sử dụng trong bài tập.
/// </summary>
public static class RsaCryptoService
{
    public const int AssignmentMaximumBytes = 190;

    public static int GetMaximumInputBytes(RSA rsa)
    {
        int k = rsa.KeySize / 8;
        int oaepSha256Limit = k - 2 * 32 - 2;
        return Math.Max(0, Math.Min(AssignmentMaximumBytes, oaepSha256Limit));
    }

    public static byte[] Encrypt(byte[] data, RSA publicKey)
    {
        int limit = GetMaximumInputBytes(publicKey);
        if (data.Length > limit)
            throw new ArgumentException($"Dữ liệu có {data.Length} byte; giới hạn với khóa hiện tại là {limit} byte (RSA-OAEP-SHA256).", nameof(data));
        return publicKey.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
    }

    public static byte[] Decrypt(byte[] cipher, RSA privateKey)
    {
        return privateKey.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);
    }

    public static bool VerifySignature(byte[] data, byte[] signature, RSA publicKey)
    {
        return publicKey.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    public static byte[] Sign(byte[] data, RSA privateKey)
    {
        return privateKey.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }
}
