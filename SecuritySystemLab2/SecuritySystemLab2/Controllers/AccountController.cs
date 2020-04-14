using System;
using System.Data.Entity;
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
    [Authorize(Roles = "User")]
    public class AccountController : Controller
    {
        private readonly AccountModel db;
        public AccountController()
        {
            db = new AccountModel();
        }

        public ActionResult Main(ManageMessageId? message)
        {
            ViewBag.StatusMessage =
                message == ManageMessageId.ChangePasswordSuccess ? "Ваш пароль изменен."              
                : message == ManageMessageId.Error ? "Произошла ошибка."             
                : "";
            return View();
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
                    var rolesArray = Roles.GetRolesForUser(User.Identity.Name);
                    Roles.CreateRole("User");

                    //Roles.AddUserToRole(User.Identity.Name, "Member");
                    //RolePrincipal r = (RolePrincipal)User;
                    //var rolesArray1 = r.GetRoles();
                    return RedirectToLocal(returnUrl);
                }
                else
                {
                    ModelState.AddModelError("", "Неверный логин или пароль.");
                    return View(model);
                }                
            }            
        }

        [AllowAnonymous]
        public ActionResult Register()
        {
            return View();
        }

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
                    Roles.AddUserToRole(model.Email, "User");
                    FormsAuthentication.SetAuthCookie(model.Email, false);
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("", "Уже существует пользователь з данным логином.");
                    return View(model);
                }
               
            }
            return View(model);
        }

        public ActionResult ChangePassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var list = db.Accounts.Where(a => a.Login == User.Identity.Name).Take(1).ToList();
            if (list.Count != 0)
            {
                Account account = list[0];
                byte[] empty = null;
                byte[] key = null;
                using (FileStream fstream = new FileStream(@"C:\Users\Valentine\source\repos\SecuritySystemLab1\SecuritySystemLab1\note.txt", FileMode.Open))
                {
                    key = new byte[fstream.Length];
                    fstream.Read(key, 0, key.Length);
                }

                var decrypted = SecretAead.Decrypt(list[0].Password, list[0].Nonce, key, null);

                if (PasswordHash.ArgonHashStringVerify(Encoding.UTF8.GetString(decrypted), Encoding.UTF8.GetString(GenericHash.Hash(model.OldPassword, empty, 32))))
                {
                    var nonce = SecretAead.GenerateNonce();
                    var encrypted = SecretAead.Encrypt(Encoding.UTF8.GetBytes(
                        PasswordHash.ArgonHashString(Encoding.UTF8.GetString(GenericHash.Hash(model.NewPassword, empty, 32)),
                        PasswordHash.StrengthArgon.Interactive)), nonce, key, null);
                    account.Nonce = nonce;
                    account.Password = encrypted;
                    db.Entry(account).State = EntityState.Modified;
                    db.SaveChanges();

                    return RedirectToAction("Main", new { Message = ManageMessageId.ChangePasswordSuccess });
                }
            }
            else
            {
                ModelState.AddModelError("", "Произошла ошибка.");
                return View(model);
            }
            return View(model);
        }

        public ActionResult DeleteAccount()
        {
            return View();
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteAccount(DeleteViewModel model)
        {
            var list = db.Accounts.Where(a => a.Login == User.Identity.Name).Take(1).ToList();
            if (list.Count != 0)
            {
                Account account = list[0];
                
                db.Accounts.Remove(account);
                db.SaveChanges();
                if (Roles.GetRolesForUser(account.Login).Length != 0)
                {
                    Roles.RemoveUserFromRoles(account.Login, Roles.GetRolesForUser(account.Login));
                }
                FormsAuthentication.SignOut();
                return RedirectToAction("Index", "Home");
            }            
            else
            {
                ModelState.AddModelError("", "Произошла ошибка.");
                return View(model);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Index", "Home");
        }

        

        #region Additional functions         
        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return RedirectToAction("Index", "Home");
        }

        public enum ManageMessageId
        {
            ChangePasswordSuccess,
            Error
        }

        #endregion
    }
}