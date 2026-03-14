interface Props {
  allBackendIds: string[];
  activeFilter: string | null;
  onToggle: (id: string | null) => void;
}

export default function BackendFilterBar({ allBackendIds, activeFilter, onToggle }: Props) {
  if (allBackendIds.length <= 1) return null;

  return (
    <div className="backend-tabs">
      {allBackendIds.map((id) => (
        <button
          key={id}
          className={`backend-tab${activeFilter === id ? " active" : ""}`}
          onClick={() => onToggle(activeFilter === id ? null : id)}
        >
          {id}
        </button>
      ))}
    </div>
  );
}
