using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO;

namespace TestRSA
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        /// <summary>
        /// 生成RSA公钥和私钥
        /// </summary>
        private void CreateRSAKey()
        {
            try
            {
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                //生成私有密钥,这个文件是要保密的
                using (StreamWriter writer = new StreamWriter("PrivateKey.xml"))
                {
                    writer.WriteLine(rsa.ToXmlString(true));
                    writer.Close();
                }

                //生成公有密钥,可以公开
                using (StreamWriter writer = new StreamWriter("PublicKey.xml"))
                {
                    writer.WriteLine(rsa.ToXmlString(false));
                    writer.Close();
                }
                //这个可以没有
                MessageBox.Show("公有密钥和私有密钥生成成功!", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        /// <summary>
        /// RSA加密(使用公有密钥进行加密)
        /// </summary>
        /// <param name="privatekey">私有密钥</param>
        /// <param name="content">要加密的字符串</param>
        /// <returns>加密后的字符串</returns>
        public static string RSAEncrypt(string publickey, string content)
        {

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            byte[] cipherbytes;
            rsa.FromXmlString(publickey);
            cipherbytes = rsa.Encrypt(Encoding.UTF8.GetBytes(content), false);
            return Convert.ToBase64String(cipherbytes);

        }

        /// <summary>
        /// RSA解密
        /// </summary>
        /// <param name="publickey">私有密钥</param>
        /// <param name="content">私有密钥加密过的字符串</param>
        /// <returns>解密后的字符串</returns>
        public static string RSADecrypt(string privatekey, string content)
        {
            try
            {
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                byte[] cipherbytes;
                rsa.FromXmlString(privatekey);
                cipherbytes = rsa.Decrypt(Convert.FromBase64String(content), false);
                return Encoding.UTF8.GetString(cipherbytes);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
                return "";
            }

        }

        /// <summary>
        /// 对字符串进行SHA1加密
        /// </summary>
        /// <param name="str_source">原字符串</param>
        /// <returns>加密后的字符串</returns>
        public static string getHash(string str_source)
        {
            HashAlgorithm ha = HashAlgorithm.Create("MD5");
            byte[] bytes = Encoding.GetEncoding(0).GetBytes(str_source);
            byte[] str_hash = ha.ComputeHash(bytes);
            return Convert.ToBase64String(str_hash);
        }

        /// <summary>
        /// 对SHA1加密后的字符串进行RSA签名
        /// </summary>
        /// <param name="privatekey">私有密钥</param>
        /// <param name="str_HashbyteSingture">SHA1加密后的字符串</param>
        /// <returns>签名后的数据</returns>
        public string SignatureFormatter(string privatekey, string str_HashbyteSingture)
        {
            byte[] rgbHash = Convert.FromBase64String(str_HashbyteSingture);
            RSACryptoServiceProvider key = new RSACryptoServiceProvider();
            key.FromXmlString(privatekey);
            RSAPKCS1SignatureFormatter rsa_formatter = new RSAPKCS1SignatureFormatter(key);
            rsa_formatter.SetHashAlgorithm("MD5");
            byte[] bytes = rsa_formatter.CreateSignature(rgbHash);
            return Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// 对RSA签名进行验证
        /// </summary>
        /// <param name="publickey">公有密钥</param>
        /// <param name="strHashbyteDeformatter">SHA1加密后的字符串</param>
        /// <param name="strDeformatterData">RSA签名后的字符串</param>
        /// <returns></returns>
        public bool SignatureDeformatter(string publickey, string strHashbyteDeformatter, string strDeformatterData)
        {
            byte[] rgbHash = Convert.FromBase64String(strHashbyteDeformatter);
            RSACryptoServiceProvider key = new RSACryptoServiceProvider();
            key.FromXmlString(publickey);
            RSAPKCS1SignatureDeformatter rsa_Deformatter = new RSAPKCS1SignatureDeformatter(key);
            rsa_Deformatter.SetHashAlgorithm("MD5");
            byte[] rgbSignature = Convert.FromBase64String(strDeformatterData);
            if (rsa_Deformatter.VerifySignature(rgbHash, rgbSignature))
            {
                return true;
            }
            return false;
        }



        private void button1_Click(object sender, EventArgs e)
        {
            CreateRSAKey();
        }

        private void button2_Click(object sender, EventArgs e)
        {
            //读取公有密钥 进行加密
            StreamReader sr = new StreamReader(@"PublicKey.xml");
            string publicKey = sr.ReadLine();
            sr.Close();
            this.textBox2.Text = RSAEncrypt(publicKey, this.textBox1.Text);
        }

        private void button3_Click(object sender, EventArgs e)
        {
            //读取私有密钥 进行解密
            StreamReader sr = new StreamReader(@"PrivateKey.xml");
            string privateKey = sr.ReadLine();
            sr.Close();
            this.textBox3.Text = RSADecrypt(privateKey, this.textBox2.Text);
        }

        private void button4_Click(object sender, EventArgs e)
        {
            //SHA1加密
            this.textBox4.Text = getHash(this.textBox1.Text);
        }

        private void button5_Click(object sender, EventArgs e)
        {
            //读取私有密钥 进行签名
            StreamReader sr = new StreamReader(@"PrivateKey.xml");
            string privatekey = sr.ReadLine();
            sr.Close();
            this.textBox5.Text = this.SignatureFormatter(privatekey, this.textBox4.Text);
        }

        private void button6_Click(object sender, EventArgs e)
        {
            StreamReader sr = new StreamReader(@"PublicKey.xml");
            string publickey = sr.ReadLine();
            sr.Close();
            this.textBox6.Text = SignatureDeformatter(publickey, this.textBox4.Text, textBox5.Text).ToString();
        }
    }
}
