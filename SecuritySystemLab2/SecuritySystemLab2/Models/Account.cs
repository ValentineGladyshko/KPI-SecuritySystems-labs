namespace SecuritySystemLab1.Models
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel.DataAnnotations;
    using System.ComponentModel.DataAnnotations.Schema;
    using System.Data.Entity.Spatial;

    public partial class Account
    {
        public int AccountId { get; set; }

        [Required]
        [Index(IsUnique = true)]
        [StringLength(128)]
        public string Login { get; set; }

        [Required]
        [MaxLength(144)]
        public byte[] Password { get; set; }

        [Required]
        [MaxLength(8)]
        public byte[] Nonce { get; set; }
    }
}
