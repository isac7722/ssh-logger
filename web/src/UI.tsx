import { useEffect, useId, useRef, useState, type ReactNode } from "react";

const paths = {
  overview: "M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
  sessions: "M4 7h16m-4-4 4 4-4 4M20 17H4m4-4-4 4 4 4",
  events: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01",
  servers: "M3 3h18v7H3z M3 14h18v7H3z M7 6.5h.01M7 17.5h.01",
  settings: "M4 7h16M4 17h16M8 4v6M16 14v6",
  accounts:
    "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M16 3a4 4 0 0 1 0 8M22 21v-2a4 4 0 0 0-3-3.87M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0",
  firewall: "M12 3 3 7v5c0 5 9 9 9 9s9-4 9-9V7l-9-4Z M9 12l2 2 4-4",
  plus: "M12 5v14M5 12h14",
  check: "m5 12 4 4L19 6",
  key: "M15 7h.01M21 7a5 5 0 0 1-7.5 4.33L5 20H2v-3l8.67-8.5A5 5 0 1 1 21 7Z",
  info: "M12 8h.01M12 11v6M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0",
  close: "m6 6 12 12M6 18 18 6",
  lock: "M5 10h14v11H5z M8 10V6a4 4 0 0 1 8 0v4",
  history: "M3 11a9 9 0 1 1 2.6 7.4M3 4v7h7M12 7v5l3 2",
} as const;

export function Icon({ name }: { name: keyof typeof paths }) {
  return (
    <svg
      className="ui-icon"
      width="20"
      height="20"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={paths[name]} />
    </svg>
  );
}

// Native dialog contains focus; restore the opener explicitly after React unmounts it.
export function Dialog({
  title,
  description,
  children,
  onClose,
  busy = false,
}: {
  title: string;
  description?: string;
  children: ReactNode;
  onClose: () => void;
  busy?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const id = useId();
  useEffect(() => {
    const dialog = ref.current!;
    const overflow = document.body.style.overflow;
    const opener = document.activeElement;
    dialog.showModal();
    document.body.style.overflow = "hidden";
    return () => {
      dialog.close();
      document.body.style.overflow = overflow;
      if (opener instanceof HTMLElement && opener.isConnected) opener.focus();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      className="ui-dialog"
      aria-labelledby={id}
      aria-describedby={description ? `${id}-description` : undefined}
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onClose();
      }}
    >
      <div className="dialog-heading">
        <div>
          <h2 id={id}>{title}</h2>
          {description && <p id={`${id}-description`}>{description}</p>}
        </div>
        <button
          type="button"
          className="icon-button"
          aria-label="닫기"
          disabled={busy}
          onClick={onClose}
        >
          <Icon name="close" />
        </button>
      </div>
      <div className="dialog-body">{children}</div>
    </dialog>
  );
}

export function PasswordField({
  label,
  value,
  onChange,
  current = false,
  error,
  hint,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  current?: boolean;
  error?: string;
  hint?: string;
}) {
  const [visible, setVisible] = useState(false);
  const id = useId();
  return (
    <div className="form-field">
      <label htmlFor={id}>{label}</label>
      <div className="password-input">
        <input
          id={id}
          type={visible ? "text" : "password"}
          autoComplete={current ? "current-password" : "new-password"}
          value={value}
          onChange={(event) => onChange(event.target.value)}
          required
          aria-invalid={!!error}
          aria-describedby={error || hint ? `${id}-help` : undefined}
        />
        <button
          type="button"
          aria-label={`${label} ${visible ? "숨기기" : "표시"}`}
          aria-pressed={visible}
          onClick={() => setVisible(!visible)}
        >
          {visible ? "숨기기" : "표시"}
        </button>
      </div>
      {(error || hint) && (
        <small
          id={`${id}-help`}
          className={error ? "field-error" : "field-hint"}
          role={error ? "alert" : undefined}
        >
          {error || hint}
        </small>
      )}
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  children,
}: {
  icon: keyof typeof paths;
  title: string;
  children?: ReactNode;
}) {
  return (
    <div className="ui-empty">
      <span className="empty-icon">
        <Icon name={icon} />
      </span>
      <h3>{title}</h3>
      {children && <p>{children}</p>}
    </div>
  );
}
