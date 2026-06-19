use std::collections::HashMap;

use uuid::Uuid;

pub trait Sessions {
    fn create_session(&mut self, user_uuid: &str) -> String;
    fn delete_session(&mut self, session: &str);
}

#[derive(Default)]
pub struct SessionsImpl {
    uuid_to_session: HashMap<String, String>,
}

impl Sessions for SessionsImpl {
    /// Create a session (a uuid) for the given `user_uuid`, and update the hashmap.
    fn create_session(&mut self, user_uuid: &str) -> String {
        let session = Uuid::new_v4().to_string();

        self.uuid_to_session
            .insert(user_uuid.to_owned(), session.clone());

        session
    }

    /// Remove the given `session`.
    fn delete_session(&mut self, session: &str) {
        self.uuid_to_session.retain(|_, sess| sess != session);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_session() {
        let mut session_service = SessionsImpl::default();
        assert_eq!(session_service.uuid_to_session.len(), 0);
        let session = session_service.create_session("123456");
        assert_eq!(session_service.uuid_to_session.len(), 1);
        assert_eq!(
            session_service.uuid_to_session.get("123456").unwrap(),
            &session
        );
    }

    #[test]
    fn should_delete_session() {
        let mut session_service = SessionsImpl::default();
        let session = session_service.create_session("123456");
        session_service.delete_session(&session);
        assert_eq!(session_service.uuid_to_session.len(), 0);
    }
}
