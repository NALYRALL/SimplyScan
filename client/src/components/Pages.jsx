import PageResult from "./PageResult";

function Pages({ pages }) {
  return (
    <div className="pages">
      <h2>Scanned Pages</h2>

      {pages.map((page, index) => (
        <PageResult
          key={index}
          page={page}
        />
      ))}
    </div>
  );
}

export default Pages;