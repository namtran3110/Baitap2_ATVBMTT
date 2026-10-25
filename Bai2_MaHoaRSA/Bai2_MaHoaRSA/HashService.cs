using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Bai2_MaHoaRSA;

public static class HashService
{
    public static byte[] ComputeSha256(byte[] data) => SHA256.HashData(data);

    public static string ComputeSha256Hex(string text)
    {
        return Convert.ToHexString(ComputeSha256(Encoding.UTF8.GetBytes(text)));
    }

    public static int CountDifferentBits(byte[] hashA, byte[] hashB)
    {
        if (hashA.Length != hashB.Length)
            throw new ArgumentException("Hai giá trị băm phải có cùng độ dài.");

        int count = 0;
        for (int i = 0; i < hashA.Length; i++)
            count += BitOperations.PopCount((uint)(hashA[i] ^ hashB[i]));
        return count;
    }
}
