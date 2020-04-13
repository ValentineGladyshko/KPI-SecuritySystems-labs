using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using Microsoft.AspNet.Identity;
using SecuritySystemLab1.Models;
using Sodium;

namespace SecuritySystemLab1.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly AccountModel db;
        public AccountController()
        {
            db = new AccountModel();
        }
         

        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ViewBag.ReturnUrl = returnUrl;
            return View();
        }

        
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Login(LoginViewModel model, string returnUrl)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var list = db.Accounts.Where(a => a.Login == model.Email).Take(1).ToList();
            if (list.Count == 0)
            {
                ModelState.AddModelError("", "Такой аккаунт не существует.");
                return View(model);
            }
            else
            {
                byte[] empty = null;
                byte[] key = null;
                using (FileStream fstream = new FileStream(@"C:\Users\Valentine\source\repos\SecuritySystemLab1\SecuritySystemLab1\note.txt", FileMode.Open))
                {
                    key = new byte[fstream.Length];
                    fstream.Read(key, 0, key.Length);
                }

                var decrypted = SecretAead.Decrypt(list[0].Password, list[0].Nonce, key, null);

                if (PasswordHash.ArgonHashStringVerify(Encoding.UTF8.GetString(decrypted), Encoding.UTF8.GetString(GenericHash.Hash(model.Password, empty, 32))))
                {
                    FormsAuthentication.SetAuthCookie(model.Email, false);
                    return RedirectToLocal(returnUrl);
                }
                else
                {
                    ModelState.AddModelError("", "Неверный логин или пароль.");
                    return View(model);
                }                
            }            
        }

        //
        // GET: /Account/Register
        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

        //
        // POST: /Account/Register
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                Account account = new Account();
                account.Login = model.Email;
                var list = db.Accounts.Where(a => a.Login == model.Email).Take(1).ToList();
                if (list.Count == 0)
                {
                    byte[] empty = null;
                    byte[] key = null;
                    using (FileStream fstream = new FileStream(@"C:\Users\Valentine\source\repos\SecuritySystemLab1\SecuritySystemLab1\note.txt", FileMode.Open))
                    {
                        key = new byte[fstream.Length];
                        fstream.Read(key, 0, key.Length);
                    }

                    var nonce = SecretAead.GenerateNonce();
                    var encrypted = SecretAead.Encrypt(Encoding.UTF8.GetBytes(
                        PasswordHash.ArgonHashString(Encoding.UTF8.GetString(GenericHash.Hash(model.Password, empty, 32)),
                        PasswordHash.StrengthArgon.Interactive)), nonce, key, null);
                    account.Nonce = nonce;
                    account.Password = encrypted;
                    db.Accounts.Add(account);
                    db.SaveChanges();
                    FormsAuthentication.SetAuthCookie(model.Email, false);
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("", "Уже существует пользователь з данным логином.");
                    return View(model);
                }
                //var user = new ApplicationUser { UserName = model.Email, Email = model.Email };
                //var result = await UserManager.CreateAsync(user, model.Password);
                //if (result.Succeeded)
                //{
                //    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: false);

                //    return RedirectToAction("Index", "Home");
                //}
                //AddErrors(result);
            }

            // Появление этого сообщения означает наличие ошибки; повторное отображение формы
            return View(model);
        }

        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Index", "Home");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                //if (_userManager != null)
                //{
                //    _userManager.Dispose();
                //    _userManager = null;
                //}

                //if (_signInManager != null)
                //{
                //    _signInManager.Dispose();
                //    _signInManager = null;
                //}
            }

            base.Dispose(disposing);
        }

        #region Вспомогательные приложения
        // Используется для защиты от XSRF-атак при добавлении внешних имен входа
        private const string XsrfKey = "XsrfId";

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        internal class ChallengeResult : HttpUnauthorizedResult
        {
            public ChallengeResult(string provider, string redirectUri)
                : this(provider, redirectUri, null)
            {
            }

            public ChallengeResult(string provider, string redirectUri, string userId)
            {
                LoginProvider = provider;
                RedirectUri = redirectUri;
                UserId = userId;
            }

            public string LoginProvider { get; set; }
            public string RedirectUri { get; set; }
            public string UserId { get; set; }
        }
        #endregion
    }
}