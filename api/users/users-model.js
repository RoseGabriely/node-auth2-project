const db = require("../../data/db-config.js");

function find() {
  return db("users as u")
    .join("roles as r", "u.role_id", "r.role_id")
    .select("user_id", "username", "role_name");
}

function findBy(filter) {
  /**
  You will need to join two tables.
  Resolves to an ARRAY with all users that match the filter condition.

  [
    {
      "user_id": 1,
      "username": "bob",
      "password": "$2a$10$dFwWjD8hi8K2I9/Y65MWi.WU0qn9eAVaiBoRSShTvuJVGw8XpsCiq",
      "role_name": "admin",
    }
  ]
 */
}

function findById(user_id) {
  return db("users as u")
    .join("roles as r", "u.role_id", "r.role_id")
    .select("user_id", "username", "role_name")
    .where("u.user_id", user_id)
    .first();
}

async function add({ username, password, role_name }) {
  let created_user_id;
  await db.transaction(async (trx) => {
    let role_id_to_use;
    const [role] = await trx("roles").where("role_name", role_name);
    if (role) {
      role_id_to_use = role.role_id;
    } else {
      const [role_id] = await trx("roles").insert({ role_name: role_name });
      role_id_to_use = role_id;
    }
    const [user_id] = await trx("users").insert({
      username,
      password,
      role_id: role_id_to_use,
    });
    created_user_id = user_id;
  });
  return findById(created_user_id);
}

module.exports = {
  add,
  find,
  findBy,
  findById,
};
