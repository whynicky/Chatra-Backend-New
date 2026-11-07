-- Account-wide subject pins, including unpins that suppress stale browser imports.
CREATE TABLE IF NOT EXISTS class_pins (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    class_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    pinned BOOLEAN NOT NULL,
    pinned_at TIMESTAMP NOT NULL,
    PRIMARY KEY (user_id, class_id)
);

CREATE INDEX IF NOT EXISTS ix_class_pins_class_id ON class_pins(class_id);
