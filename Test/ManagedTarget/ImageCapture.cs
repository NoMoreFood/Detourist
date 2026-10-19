#if NET48
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;

internal static class ManagedImageCapture
{
    internal static int Run(string result)
    {
        // Image decoding passes a managed IStream through native WIC objects and back into CLR.
        for (var index = 0; index < 20; ++index)
        {
            using (var buffer = new MemoryStream())
            using (var source = new Bitmap(16, 16))
            {
                source.SetPixel(3, 4, Color.Red);
                source.Save(buffer, ImageFormat.Png);
                buffer.Position = 0;
                using (var image = Image.FromStream(buffer, false, true))
                using (var bitmap = new Bitmap(image))
                    if (bitmap.GetPixel(3, 4).ToArgb() != Color.Red.ToArgb()) return 1;
            }
        }
        File.WriteAllText(result, "image-ok");
        return 0;
    }
}
#endif
