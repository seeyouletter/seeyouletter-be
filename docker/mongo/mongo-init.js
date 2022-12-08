db.createUser(
    {
        user: "app",
        pwd: "1234",
        roles: [
            {
                role: "dbOwner",
                db: "seeyouletter"
            }
        ]
    }
);