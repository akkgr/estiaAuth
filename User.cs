using System;
using System.Collections.Generic;
using System.Security.Claims;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace estiaAuth
{
    [BsonIgnoreExtraElements]
    public class User
    {
        public User()
        {
            Claims = new List<Claim>();
        }

        [BsonId]
        [BsonRepresentation(BsonType.ObjectId)]
        public string Id { get; set; }

        [BsonElement("username")]
        public string Username { get; set; }

        [BsonElement("password")]
        public string Password { get; set; }

        [BsonElement("providerName")]
        public string ProviderName { get; set; }

        [BsonElement("providerSubjectId")]
        public string ProviderSubjectId { get; set; }

        [BsonElement("claims")]
        public List<Claim> Claims { get; set; }
    }
}