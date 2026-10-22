//! Service-Linked Role Builder

use super::model::*;

/// Build a deletion task for the role stored under `role`.
pub fn build_deletion_task(role: &crate::arn::ScopedName) -> DeletionTaskInfo {
    let deletion_task_id = uuid::Uuid::new_v4().to_string();

    DeletionTaskInfo {
        deletion_task_id,
        status: DeletionTaskStatus::InProgress,
        role: role.clone(),
        failure_reason: None,
        create_date: chrono::Utc::now(),
    }
}
