use sqlx::PgPool;

use crate::structs::DnsAnswer;

impl DnsAnswer {
    pub async fn upsert(&self, pool: &PgPool) -> Result<(), sqlx::Error> {
        let rec = sqlx::query!(
            r#"
            INSERT INTO dns_answers (domain_name, ttl, record_type, read_from_buffer_ts)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (domain_name, record_type) DO UPDATE
            SET ttl = EXCLUDED.ttl,
                read_from_buffer_ts = EXCLUDED.read_from_buffer_ts
            "#,
            self.domain_name,
            self.ttl as i32,
            self.record_type.form_for_command_line_arg(), // Adjust this if necessary
            self.read_from_buffer_ts
        )
        .execute(pool)
        .await?;
        Ok(())
    }
}
